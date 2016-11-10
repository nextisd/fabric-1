/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package helper

import (
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/spf13/viper"
	"golang.org/x/net/context"

	"github.com/hyperledger/fabric/consensus"
	"github.com/hyperledger/fabric/consensus/executor"
	"github.com/hyperledger/fabric/consensus/helper/persist"
	"github.com/hyperledger/fabric/core/chaincode"
	crypto "github.com/hyperledger/fabric/core/crypto"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/core/peer"
	pb "github.com/hyperledger/fabric/protos"
)

// Helper contains the reference to the peer's MessageHandlerCoordinator
//
// Helper 구조체 : 피어의shim과 consensus.stack간의 메시지 핸들링, 타 노드와의 메시지 처리 지원.
type Helper struct {
	consenter    consensus.Consenter
	coordinator  peer.MessageHandlerCoordinator
	secOn        bool
	valid        bool // Whether we believe the state is up to date
	secHelper    crypto.Peer
	curBatch     []*pb.Transaction       // TODO, remove after issue 579
	curBatchErrs []*pb.TransactionResult // TODO, remove after issue 579
	persist.Helper

	executor consensus.Executor
}

// NewHelper constructs the consensus helper object
//
// NewHelper() : consensus helper 객체 생성
func NewHelper(mhc peer.MessageHandlerCoordinator) *Helper {
	h := &Helper{
		coordinator: mhc,
		secOn:       viper.GetBool("security.enabled"),
		secHelper:   mhc.GetSecHelper(),
		valid:       true, // Assume our state is consistent until we are told otherwise, actual consensus (pbft) will invalidate this immediately, but noops will not
		// state가 consistent하다고 가정함, 만약 아니라면 pbft에서는 바로 invalidate 상태로 변경해야 하지만 noops는 그럴 필요 없음.
	}

	// executor.NewImpl() : coordinatorImpl 생성
	// type coordinatorImpl struct {
	//	manager         events.Manager              // event thread 관리, coordinator에게 event 전송처리
	//	rawExecutor     PartialStack                // ledger에 직접 액세스
	//	consumer        consensus.ExecutionConsumer // callback 수신
	//	stc             statetransfer.Coordinator   // state 전송 객체
	//	batchInProgress bool                        // Are we mid execution batch
	//	skipInProgress  bool                        // Are we mid state transfer
	// }
	h.executor = executor.NewImpl(h, h, mhc)
	return h
}

func (h *Helper) setConsenter(c consensus.Consenter) {
	h.consenter = c
	h.executor.Start() // The consenter may be expecting a callback from the executor because of state transfer completing, it will miss this if we start the executor too early
	// state 전송 완료시 consenter는 executor로부터의 callback을 수신할 것으로 예상되지만, executor를 너무 일찍 시작하면 callback 수신을 놓칠 수도 있다.
}

// GetNetworkInfo returns the PeerEndpoints of the current validator and the entire validating network
//
// h.GetNetworkInfo() : 현재 VP와 전체 네트워크의 VP들의 PeerEndpoint를 리턴
func (h *Helper) GetNetworkInfo() (self *pb.PeerEndpoint, network []*pb.PeerEndpoint, err error) {
	ep, err := h.coordinator.GetPeerEndpoint()
	if err != nil {
		return self, network, fmt.Errorf("Couldn't retrieve own endpoint: %v", err)
	}
	self = ep

	peersMsg, err := h.coordinator.GetPeers()
	if err != nil {
		return self, network, fmt.Errorf("Couldn't retrieve list of peers: %v", err)
	}
	peers := peersMsg.GetPeers()
	for _, endpoint := range peers {
		if endpoint.Type == pb.PeerEndpoint_VALIDATOR {
			network = append(network, endpoint)
		}
	}
	network = append(network, self)

	return
}

// GetNetworkHandles returns the PeerIDs of the current validator and the entire validating network
//
// h.GetNetworkHandles() : 현재 VP와 전체 네트워크의 VP들의 PeerID를 리턴
func (h *Helper) GetNetworkHandles() (self *pb.PeerID, network []*pb.PeerID, err error) {
	selfEP, networkEP, err := h.GetNetworkInfo()
	if err != nil {
		return self, network, fmt.Errorf("Couldn't retrieve validating network's endpoints: %v", err)
	}

	self = selfEP.ID

	for _, endpoint := range networkEP {
		network = append(network, endpoint.ID)
	}
	network = append(network, self)

	return
}

// Broadcast sends a message to all validating peers
//
// h.Broadcast() : 모든 VP들에게 메시지 전송 처리.
func (h *Helper) Broadcast(msg *pb.Message, peerType pb.PeerEndpoint_Type) error {
	errors := h.coordinator.Broadcast(msg, peerType)
	if len(errors) > 0 {
		return fmt.Errorf("Couldn't broadcast successfully")
	}
	return nil
}

// Unicast sends a message to a specified receiver
func (h *Helper) Unicast(msg *pb.Message, receiverHandle *pb.PeerID) error {
	return h.coordinator.Unicast(msg, receiverHandle)
}

// Sign a message with this validator's signing key
func (h *Helper) Sign(msg []byte) ([]byte, error) {
	if h.secOn {
		return h.secHelper.Sign(msg)
	}
	logger.Debug("Security is disabled")
	return msg, nil
}

// Verify that the given signature is valid under the given replicaID's verification key
// If replicaID is nil, use this validator's verification key
// If the signature is valid, the function should return nil
//
// h.Verify() : 주어진 signature가 주어진 ReplicaID의 verification key에 유효한지를 검증.
// 만약 replicaID가 nil 이면 이 VP의 verification key를 사용한다.
// 만약 signature가 유효하면, 이 함수는 nil를 리턴해야 한다.
func (h *Helper) Verify(replicaID *pb.PeerID, signature []byte, message []byte) error {
	if !h.secOn {
		logger.Debug("Security is disabled")
		return nil
	}

	logger.Debugf("Verify message from: %v", replicaID.Name)
	_, network, err := h.GetNetworkInfo()
	if err != nil {
		return fmt.Errorf("Couldn't retrieve validating network's endpoints: %v", err)
	}

	// check that the sender is a valid replica
	// if so, call crypto verify() with that endpoint's pkiID
	//
	// sender가 valid replica인지 체크한다.
	// 만약 그렇다면 crypto.Peer.Verify(Endpoint의 pkiID)를 호출한다.
	for _, endpoint := range network {
		logger.Debugf("Endpoint name: %v", endpoint.ID.Name)
		if *replicaID == *endpoint.ID {
			cryptoID := endpoint.PkiID
			return h.secHelper.Verify(cryptoID, signature, message)
		}
	}
	return fmt.Errorf("Could not verify message from %s (unknown peer)", replicaID.Name)
}

// BeginTxBatch gets invoked when the next round
// of transaction-batch execution begins
//
// h.BeginTxBatch() : 다음 라운드 tx-batch가 시작할때 호출됨.
func (h *Helper) BeginTxBatch(id interface{}) error {
	ledger, err := ledger.GetLedger()
	if err != nil {
		return fmt.Errorf("Failed to get the ledger: %v", err)
	}
	if err := ledger.BeginTxBatch(id); err != nil {
		return fmt.Errorf("Failed to begin transaction with the ledger: %v", err)
	}
	h.curBatch = nil     // TODO, remove after issue 579
	h.curBatchErrs = nil // TODO, remove after issue 579
	return nil
}

// ExecTxs executes all the transactions listed in the txs array
// one-by-one. If all the executions are successful, it returns
// the candidate global state hash, and nil error array.
//
// h.ExecTxs() : []txs 의 모든 트랜잭션에 대해 개별로 chaincode.Execute() 처리.
// 모든 execution을 실행한 후, candidate global state hash와 error를 리턴.
// 리턴하는 error : Tx 에러 아니고, Ledger 관련 에러
func (h *Helper) ExecTxs(id interface{}, txs []*pb.Transaction) ([]byte, error) {
	// TODO id is currently ignored, fix once the underlying implementation accepts id
	// TODO @id는 현재는 무시됨, 아래 코드에서 처리 수정 예정.

	// The secHelper is set during creat ChaincodeSupport, so we don't need this step
	// cxt := context.WithValue(context.Background(), "security", h.coordinator.GetSecHelper())
	// TODO return directly once underlying implementation no longer returns []error
	//
	// secHelper는 ChaincodeSupport 생성중에 세팅됨, 그래서 이 과정이 필요 없음
	// cxt := context.WithValue(context.Background(), "security", h.coordinator.GetSecHelper())
	//@@ Tx Array 를 받아서, 개별 Tx 마다 chaincode.Execute() 호출
	//@@		ledger (blockchain) 관리 객체 얻어옴 (객체는 전역 1개)
	//@@		Confidentiality check
	//@@		CHAINCODE_DEPLOY 인 경우
	//@@			chain.Deploy(ctxt, t) 호출
	//@@				Dup Check
	//@@				VMCProcess() 호출 : 내부에서 vm.Deploy() 실행
	//@@			chain.Launch(ctxt, t) 호출
	//@@				launchAndWaitForRegister() 실행
	//@@					container.StartImageReq 생성후 VMCProcesS() 실행 ( 내부 : vm.Start() )
	//@@					readyNotify 채널에서 true 가 오면 정상, false 가 오면 실패
	//@@				sendInitOrReady() 실행
	//@@					handler.nextState 채널로 ChaincodeMessage 전송 & responseNotifier 생성
	//@@					응답수신 대기 && 에러응답 처리
	//@@		CHAINCODE_INVOKE  또는 CHAINCODE_QUERY 인 경우
	//@@			chain.Launch(ctxt, t) 호출
	//@@				launchAndWaitForRegister() 실행
	//@@					container.StartImageReq 생성후 VMCProcesS() 실행 ( 내부 : vm.Start() )
	//@@					readyNotify 채널에서 true 가 오면 정상, false 가 오면 실패
	//@@				sendInitOrReady() 실행
	//@@					handler.nextState 채널로 ChaincodeMessage 전송 & responseNotifier 생성
	//@@					응답수신 대기 && 에러응답 처리
	//@@				ChaincodeID, CtorMsg, err 리턴
	//@@			INVOKE 또는 QUERY 용 Tx Msg 생성
	//@@			chain.Execute(ctxt, chaincode, ccMsg, timeout, t) 호출
	//@@				ChaincodeID 로 *chaincodeRTEnv 를 찾지 못하면 에러 처리
	//@@				pb.Transaction 으로부터 pb.ChaincodeMessage.SecurityContext(msg) 설정
	//@@				chrte.handler.sendExecuteMessage() 실행 --> response 채널 얻기
	//@@					Tx == Transaction : handler.nextState 채널로 ChaincodeMessage 전송
	//@@					Tx != Transaction : serialSend : 체인코드 메세지를 순차적으로 송신. (Lock 처리)
	//@@					response 채널 리턴
	//@@				select : response 채널 과 timeout 채널
	//@@				handler 에서 Txid 를 삭제
	//@@				response 리턴
	//@@			return resp.Payload, resp.ChaincodeEvent,err
	succeededTxs, res, ccevents, txerrs, err := chaincode.ExecuteTransactions(context.Background(), chaincode.DefaultChain, txs)

	h.curBatch = append(h.curBatch, succeededTxs...) // TODO, remove after issue 579

	//copy errs to result
	txresults := make([]*pb.TransactionResult, len(txerrs))

	//process errors for each transaction
	for i, e := range txerrs {
		//NOTE- it'll be nice if we can have error values. For now success == 0, error == 1
		if txerrs[i] != nil {
			txresults[i] = &pb.TransactionResult{Txid: txs[i].Txid, Error: e.Error(), ErrorCode: 1, ChaincodeEvent: ccevents[i]}
		} else {
			txresults[i] = &pb.TransactionResult{Txid: txs[i].Txid, ChaincodeEvent: ccevents[i]}
		}
	}
	h.curBatchErrs = append(h.curBatchErrs, txresults...) // TODO, remove after issue 579

	return res, err
}

// CommitTxBatch gets invoked when the current transaction-batch needs
// to be committed. This function returns successfully iff the
// transactions details and state changes (that may have happened
// during execution of this transaction-batch) have been committed to
// permanent storage.
//
// h.CommitTxBatch() : 현재의 tx-batch를 커밋할때 호출됨.
// transaction detail과 state delta(tx-batch executing중에 발생한)들이 영구 스토리지에 커밋되었을때 정상 리턴
func (h *Helper) CommitTxBatch(id interface{}, metadata []byte) (*pb.Block, error) {
	ledger, err := ledger.GetLedger()
	if err != nil {
		return nil, fmt.Errorf("Failed to get the ledger: %v", err)
	}
	// TODO fix this one the ledger has been fixed to implement
	if err := ledger.CommitTxBatch(id, h.curBatch, h.curBatchErrs, metadata); err != nil {
		return nil, fmt.Errorf("Failed to commit transaction to the ledger: %v", err)
	}

	size := ledger.GetBlockchainSize()
	defer func() {
		h.curBatch = nil     // TODO, remove after issue 579
		h.curBatchErrs = nil // TODO, remove after issue 579
	}()

	block, err := ledger.GetBlockByNumber(size - 1)
	if err != nil {
		return nil, fmt.Errorf("Failed to get the block at the head of the chain: %v", err)
	}

	logger.Debugf("Committed block with %d transactions, intended to include %d", len(block.Transactions), len(h.curBatch))

	return block, nil
}

// RollbackTxBatch discards all the state changes that may have taken
// place during the execution of current transaction-batch
//
// h.RollbackTxBatch() : 현재 tx-batch 실행중 변경된 state delta들을 롤백.
func (h *Helper) RollbackTxBatch(id interface{}) error {
	ledger, err := ledger.GetLedger()
	if err != nil {
		return fmt.Errorf("Failed to get the ledger: %v", err)
	}
	if err := ledger.RollbackTxBatch(id); err != nil {
		return fmt.Errorf("Failed to rollback transaction with the ledger: %v", err)
	}
	h.curBatch = nil     // TODO, remove after issue 579
	h.curBatchErrs = nil // TODO, remove after issue 579
	return nil
}

// PreviewCommitTxBatch retrieves a preview of the block info blob (as
// returned by GetBlockchainInfoBlob) that would describe the
// blockchain if CommitTxBatch were invoked.  The blockinfo will
// change if additional ExecTXs calls are invoked.
//
// h.PreviewCommitTxBatch() : CommitTxBatch가 처리되었다고 가정하고 Block info를 리턴.
func (h *Helper) PreviewCommitTxBatch(id interface{}, metadata []byte) ([]byte, error) {
	ledger, err := ledger.GetLedger()
	if err != nil {
		return nil, fmt.Errorf("Failed to get the ledger: %v", err)
	}
	// TODO fix this once the underlying API is fixed
	blockInfo, err := ledger.GetTXBatchPreviewBlockInfo(id, h.curBatch, metadata)
	if err != nil {
		return nil, fmt.Errorf("Failed to preview commit: %v", err)
	}
	rawInfo, _ := proto.Marshal(blockInfo)
	return rawInfo, nil
}

// GetBlock returns a block from the chain
func (h *Helper) GetBlock(blockNumber uint64) (block *pb.Block, err error) {
	ledger, err := ledger.GetLedger()
	if err != nil {
		return nil, fmt.Errorf("Failed to get the ledger :%v", err)
	}
	return ledger.GetBlockByNumber(blockNumber)
}

// GetCurrentStateHash returns the current/temporary state hash
func (h *Helper) GetCurrentStateHash() (stateHash []byte, err error) {
	ledger, err := ledger.GetLedger()
	if err != nil {
		return nil, fmt.Errorf("Failed to get the ledger :%v", err)
	}
	return ledger.GetTempStateHash()
}

// GetBlockchainSize returns the current size of the blockchain
func (h *Helper) GetBlockchainSize() uint64 {
	return h.coordinator.GetBlockchainSize()
}

// GetBlockchainInfo gets the ledger's BlockchainInfo
func (h *Helper) GetBlockchainInfo() *pb.BlockchainInfo {
	ledger, _ := ledger.GetLedger()
	info, _ := ledger.GetBlockchainInfo()
	return info
}

// GetBlockchainInfoBlob marshals a ledger's BlockchainInfo into a protobuf
//
// h.GetBlockchainInfoBlob() : ledger의 BlockchainInfo를 protobuf로 마샬링
func (h *Helper) GetBlockchainInfoBlob() []byte {
	ledger, _ := ledger.GetLedger()
	info, _ := ledger.GetBlockchainInfo()
	rawInfo, _ := proto.Marshal(info)
	return rawInfo
}

// GetBlockHeadMetadata returns metadata from block at the head of the blockchain
//
// h.GetBlockHeadMetadata() : 블록체인 헤드의 metadata를 리턴.
func (h *Helper) GetBlockHeadMetadata() ([]byte, error) {
	ledger, err := ledger.GetLedger()
	if err != nil {
		return nil, err
	}
	head := ledger.GetBlockchainSize()
	block, err := ledger.GetBlockByNumber(head - 1)
	if err != nil {
		return nil, err
	}
	return block.ConsensusMetadata, nil
}

// InvalidateState is invoked to tell us that consensus realizes the ledger is out of sync
//
// h.InvalidateState() : 컨센서스가 ledger의 sync가 맞지 않다는 것이 확인되었을때 호출됨
func (h *Helper) InvalidateState() {
	logger.Debug("Invalidating the current state")
	h.valid = false
}

// ValidateState is invoked to tell us that consensus has the ledger back in sync
//
// h.ValidateState() : 컨센서스가 ledger가 sync되었다는걸 확인했을때 호출됨
func (h *Helper) ValidateState() {
	logger.Debug("Validating the current state")
	h.valid = true
}

// Execute will execute a set of transactions, this may be called in succession
//
// h.Execute() : @txs들을 execute, 연속적으로 호출될 수 있음.
func (h *Helper) Execute(tag interface{}, txs []*pb.Transaction) {
	h.executor.Execute(tag, txs)
}

// Commit will commit whatever transactions have been executed
//
// h.Commit() : execute된 tx들을 커밋
func (h *Helper) Commit(tag interface{}, metadata []byte) {
	h.executor.Commit(tag, metadata)
}

// Rollback will roll back whatever transactions have been executed
//
// h.Rollback() : execute된 tx들을 롤백.
func (h *Helper) Rollback(tag interface{}) {
	h.executor.Rollback(tag)
}

// UpdateState attempts to synchronize state to a particular target, implicitly calls rollback if needed
//
// h.UpdateState() : @target에 state 동기화를 시도, 필요한 경우 롤백 처리.
func (h *Helper) UpdateState(tag interface{}, target *pb.BlockchainInfo, peers []*pb.PeerID) {
	if h.valid {
		logger.Warning("State transfer is being called for, but the state has not been invalidated")
	}

	h.executor.UpdateState(tag, target, peers)
}

// Executed is called whenever Execute completes
func (h *Helper) Executed(tag interface{}) {
	if h.consenter != nil {
		h.consenter.Executed(tag)
	}
}

// Committed is called whenever Commit completes
func (h *Helper) Committed(tag interface{}, target *pb.BlockchainInfo) {
	if h.consenter != nil {
		h.consenter.Committed(tag, target)
	}
}

// RolledBack is called whenever a Rollback completes
func (h *Helper) RolledBack(tag interface{}) {
	if h.consenter != nil {
		h.consenter.RolledBack(tag)
	}
}

// StateUpdated is called when state transfer completes, if target is nil, this indicates a failure and a new target should be supplied
//
// h.StateUpdate() : state 전송이 완료되었을때 호출됨. @target이 nil이면 전송 실패를 뜻하고 새로운 @target이 필요함.
func (h *Helper) StateUpdated(tag interface{}, target *pb.BlockchainInfo) {
	if h.consenter != nil {
		h.consenter.StateUpdated(tag, target)
	}
}

// Start his is a byproduct of the consensus API needing some cleaning, for now it's a no-op
func (h *Helper) Start() {}

// Halt is a byproduct of the consensus API needing some cleaning, for now it's a no-op
func (h *Helper) Halt() {}
