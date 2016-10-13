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

package noops

import (
	"fmt"
	"strconv"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/op/go-logging"

	"github.com/hyperledger/fabric/consensus"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/core/ledger/statemgmt"
	"github.com/hyperledger/fabric/core/util"
	pb "github.com/hyperledger/fabric/protos"
)

var logger *logging.Logger // package-level logger

func init() {
	logger = logging.MustGetLogger("consensus/noops")
}

// Noops is a plugin object implementing the consensus.Consenter interface.
//
// Noops 구조체 : consensus.Consenter 인터페이스 구현.
// 현재는 PBFT/Noops 2개의 컨센서스 알고리즘을 플러그인으로 제공.
// Noops : 개발용 dummy 플러그인, 컨센서스를 하지 않지만 모든 컨센서스 메시지를 처리함.
type Noops struct {
	// 컨센서스에서 사용하는 method들의 스택 인터페이스
	// NetworkStack, SecurityUtils, Executor, LegacyExecutor, LedgerManager, ReadOnlyLedger, StatePersistor.
	stack    consensus.Stack
	txQ      *txq // 트랜잭션 큐
	timer    *time.Timer
	duration time.Duration
	channel  chan *pb.Transaction
}

// Setting up a singleton NOOPS consenter
//
// consensus.Consenter : N/W에서 메시지를 수신하는 인터페이스
var iNoops consensus.Consenter

// GetNoops returns a singleton of NOOPS
//
// GetNoops() : Noops 싱글턴(consensus.Consenter) 객체 리턴
func GetNoops(c consensus.Stack) consensus.Consenter {
	if iNoops == nil {
		iNoops = newNoops(c)
	}
	return iNoops
}

// newNoops is a constructor returning a consensus.Consenter object.
//
// newNoops() : consensus.Consenter 객체 생성
func newNoops(c consensus.Stack) consensus.Consenter {
	var err error
	if logger.IsEnabledFor(logging.DEBUG) {
		logger.Debug("Creating a NOOPS object")
	}
	i := &Noops{}
	i.stack = c
	config := loadConfig()
	blockSize := config.GetInt("block.size")    // 블록에 들어갈 트랜잭션 개수 세팅값
	blockWait := config.GetString("block.wait") // 블록생성주기
	if _, err = strconv.Atoi(blockWait); err == nil {
		blockWait = blockWait + "s" //if string does not have unit of measure, default to seconds
	}
	i.duration, err = time.ParseDuration(blockWait)
	if err != nil || i.duration == 0 {
		panic(fmt.Errorf("Cannot parse block wait: %s", err))
	}

	logger.Infof("NOOPS consensus type = %T", i)
	logger.Infof("NOOPS block size = %v", blockSize)
	logger.Infof("NOOPS block wait = %v", i.duration)

	i.txQ = newTXQ(blockSize) // 트랜잭션 큐 생성

	i.channel = make(chan *pb.Transaction, 100) // 트랜잭션 채널 생성
	i.timer = time.NewTimer(i.duration)         // start timer now so we can just reset it
	i.timer.Stop()                              // 타이머 생성
	go i.handleChannels()                       // 고루틴: tx 채널 상태를 확인후 블록생성 및 전파(to NVPs)
	return i
}

// RecvMsg is called for Message_CHAIN_TRANSACTION and Message_CONSENSUS messages.
//
// i.RecvMsg() : consenter.RecvMsg() 구현, 메시지 수신시마다 gRPC로 부터 호출됨
// 	Message_CHAIN_TRANSACTION : 유저에게 response 메시지를 먼저 보내주고, consentor.RecvMsg(msg) 호출(e.g. external deploy request)
// 	Message_CONSENSUS : consenter.RecvMsg(msg) 바로 호출
func (i *Noops) RecvMsg(msg *pb.Message, senderHandle *pb.PeerID) error {
	if logger.IsEnabledFor(logging.DEBUG) {
		logger.Debugf("Handling Message of type: %s ", msg.Type)
	}
	if msg.Type == pb.Message_CHAIN_TRANSACTION {
		// VP들에게 CONSENSUS 메시지를 Broadcast
		if err := i.broadcastConsensusMsg(msg); nil != err {
			return err
		}
	}
	if msg.Type == pb.Message_CONSENSUS {
		// @msg로부터 tx 추출
		tx, err := i.getTxFromMsg(msg)
		if nil != err {
			return err
		}
		if logger.IsEnabledFor(logging.DEBUG) {
			logger.Debugf("Sending to channel tx uuid: %s", tx.Txid)
		}
		// 추출된 tx를 Noops 채널에 던짐
		i.channel <- tx
	}
	return nil
}

// i.broadcastConsensusMsg() : CONSENSUS 메시지를 VP들에게 Broadcast.
func (i *Noops) broadcastConsensusMsg(msg *pb.Message) error {
	t := &pb.Transaction{}
	if err := proto.Unmarshal(msg.Payload, t); err != nil {
		return fmt.Errorf("Error unmarshalling payload of received Message:%s.", msg.Type)
	}

	// Change the msg type to consensus and broadcast to the network so that
	// other validators may execute the transaction
	// 메시지 타입을 Message_CONSENSUS로 변경하고, 다른 VP들이 트랜잭션을 execute 할수 있도록, broadcast 처리.
	msg.Type = pb.Message_CONSENSUS
	if logger.IsEnabledFor(logging.DEBUG) {
		logger.Debugf("Broadcasting %s", msg.Type)
	}
	txs := &pb.TransactionBlock{Transactions: []*pb.Transaction{t}}
	payload, err := proto.Marshal(txs)
	if err != nil {
		return err
	}
	msg.Payload = payload
	// 모든 VP에게 broadcast
	if errs := i.stack.Broadcast(msg, pb.PeerEndpoint_VALIDATOR); nil != errs {
		return fmt.Errorf("Failed to broadcast with errors: %v", errs)
	}
	return nil
}

// i.canProcessBlock() : 블록생성처리를 할지 체크(blocksize 체크)
func (i *Noops) canProcessBlock(tx *pb.Transaction) bool {
	// For NOOPS, if we have completed the sync since we last connected,
	// we can assume that we are at the current state; otherwise, we need to
	// wait for the sync process to complete before we can exec the transactions
	//
	// Noops에서는 동기화(sync)가 완료되었을 경우, current state가 되었다고 가정할 수 있다.
	// 그렇지 않다면, 트랜잭션 실행전에 sync process가 종료되기를 기다려야 한다.

	// TODO: Ask coordinator if we need to start sync

	i.txQ.append(tx)

	// start timer if we get a tx
	//
	// tx가 들어오면 타이머 시작
	if i.txQ.size() == 1 {
		i.timer.Reset(i.duration)
	}
	return i.txQ.isFull() // tx 개수가 가득찼을경우 true
}

// i.handleChannels() : tx 채널 상태를 확인후 블록생성 및 전파(to NVPs)
func (i *Noops) handleChannels() {
	// Noops is a singleton object and only exits when peer exits, so we
	// don't need a condition to exit this loop
	//
	// Noops은 싱글턴 객체로서 피어가 종료될때 같이 종료되므로,
	// 아래 루프의 종료 조건을 설정할 필요가 없음.
	for {
		select {
		// 채널에 tx가 있을경우
		case tx := <-i.channel:
			// tx 개수가 가득찼을경우(config.yaml: block.size)
			if i.canProcessBlock(tx) {
				if logger.IsEnabledFor(logging.DEBUG) {
					logger.Debug("Process block due to size")
				}
				// tx실행, 블록생성, 네트워크에 전파
				if err := i.processBlock(); nil != err {
					logger.Error(err.Error())
				}
			}
		// 타이머가 duration(config.yaml : block.wait) 경과시
		case <-i.timer.C:
			if logger.IsEnabledFor(logging.DEBUG) {
				logger.Debug("Process block due to time")
			}
			// tx실행, 블록생성, 네트워크에 전파
			if err := i.processBlock(); nil != err {
				logger.Error(err.Error())
			}
		}
	}
}

// i.processBlock() : tx실행, 블록생성, 네트워크에 전파까지 실행.
func (i *Noops) processBlock() error {
	// 타이머 종료
	i.timer.Stop()

	if i.txQ.size() < 1 {
		if logger.IsEnabledFor(logging.DEBUG) {
			logger.Debug("processBlock() called but transaction Q is empty")
		}
		return nil
	}
	var data *pb.Block
	var delta *statemgmt.StateDelta
	var err error

	// 블록에 들어갈 트랜잭션들을 state/ledger에 반영(tx-batch execute/commit)
	if err = i.processTransactions(); nil != err {
		return err
	}
	// 위에서 생성한 신규 블록정보 데이터 및 그 사이 발생한 state delta 확인
	if data, delta, err = i.getBlockData(); nil != err {
		return err
	}
	// 신규 생성된 블록을 NVP들에게 Broadcast 처리
	go i.notifyBlockAdded(data, delta)
	return nil
}

// i.processTransactions() : 트랜잭션들을 트랜잭션 배치 처리 실행(state/ledger에 반영)
func (i *Noops) processTransactions() error {
	timestamp := util.CreateUtcTimestamp()
	if logger.IsEnabledFor(logging.DEBUG) {
		logger.Debugf("Starting TX batch with timestamp: %v", timestamp)
	}
	// 트랜잭션 배치 시작 마킹
	if err := i.stack.BeginTxBatch(timestamp); err != nil {
		return err
	}

	// Grab all transactions from the FIFO queue and run them in order
	//
	// 트랜잭션 FIFO 큐에서 모든 트랜잭션을 가져와서 순서대로 실행
	txarr := i.txQ.getTXs()
	if logger.IsEnabledFor(logging.DEBUG) {
		logger.Debugf("Executing batch of %d transactions with timestamp %v", len(txarr), timestamp)
	}
	// ExecTxs() : tx 배열을 입력받아서, 현재의 ledger state에 반영(chaincode.ExecuteTransactions()
	// 정상 처리시 current state hash를 리턴.
	// tx 처리중 에러 발생시 tx array에 대응되는 에러도 리턴하지만, 에러가 tx batch의 commit에 영향을 주지는 못함.
	// tx 에러에 대한 처리는 플러그인에서 정의해야 함.
	_, err := i.stack.ExecTxs(timestamp, txarr)

	//consensus does not need to understand transaction errors, errors here are
	//actual ledger errors, and often irrecoverable
	//
	// 컨센서스에서 tx 에러에 대해 이해할 필요는 없음.
	// 여기 발생한 에러들은 실제 ledger에서의 에러이고 복구불가일수도 있음.

	// tx 처리중 에러 발생시 트랜잭션 배치 롤백 후 에러 리턴
	if err != nil {
		logger.Debugf("Rolling back TX batch with timestamp: %v", timestamp)
		i.stack.RollbackTxBatch(timestamp)
		return fmt.Errorf("Fail to execute transactions: %v", err)
	}
	if logger.IsEnabledFor(logging.DEBUG) {
		logger.Debugf("Committing TX batch with timestamp: %v", timestamp)
	}
	// tx 정상처리시 트랜잭션 배치 커밋.
	if _, err := i.stack.CommitTxBatch(timestamp, nil); err != nil {
		logger.Debugf("Rolling back TX batch with timestamp: %v", timestamp)
		i.stack.RollbackTxBatch(timestamp)
		return err
	}
	return nil
}

// i.getTxFromMsg() : @msg로부터 tx들을 추출해 낸뒤, 첫번째 tx를 리턴
func (i *Noops) getTxFromMsg(msg *pb.Message) (*pb.Transaction, error) {
	txs := &pb.TransactionBlock{}
	if err := proto.Unmarshal(msg.Payload, txs); err != nil {
		return nil, err
	}
	return txs.GetTransactions()[0], nil
}

// i.getBlockData() : 트랜잭션 큐로부터 생성한 신규 블록정보 리턴
func (i *Noops) getBlockData() (*pb.Block, *statemgmt.StateDelta, error) {
	ledger, err := ledger.GetLedger()
	if err != nil {
		return nil, nil, fmt.Errorf("Fail to get the ledger: %v", err)
	}

	blockHeight := ledger.GetBlockchainSize()
	if logger.IsEnabledFor(logging.DEBUG) {
		logger.Debugf("Preparing to broadcast with block number %v", blockHeight)
	}
	block, err := ledger.GetBlockByNumber(blockHeight - 1)
	if nil != err {
		return nil, nil, err
	}
	//delta, err := ledger.GetStateDeltaBytes(blockHeight)
	delta, err := ledger.GetStateDelta(blockHeight - 1)
	if nil != err {
		return nil, nil, err
	}
	if logger.IsEnabledFor(logging.DEBUG) {
		logger.Debugf("Got the delta state of block number %v", blockHeight)
	}

	return block, delta, nil
}

// i.notifyBlockAdded() : 신규 생성된 블록을 NVP들에게 Broadcast 처리.
func (i *Noops) notifyBlockAdded(block *pb.Block, delta *statemgmt.StateDelta) error {
	//make Payload nil to reduce block size..
	//anything else to remove .. do we need StateDelta ?
	//
	// 블록 사이즈를 줄이기 위해 tx.Payload를 nil로 설정
	// 또 줄일게 없나? stateDelta 필요한가??
	for _, tx := range block.Transactions {
		tx.Payload = nil
	}
	data, err := proto.Marshal(&pb.BlockState{Block: block, StateDelta: delta.Marshal()})
	if err != nil {
		return fmt.Errorf("Fail to marshall BlockState structure: %v", err)
	}
	if logger.IsEnabledFor(logging.DEBUG) {
		logger.Debug("Broadcasting Message_SYNC_BLOCK_ADDED to non-validators")
	}

	// Broadcast SYNC_BLOCK_ADDED to connected NVPs
	// VPs already know about this newly added block since they participate
	// in the execution. That is, they can compare their current block with
	// the network block
	//
	// SYNC_BLOCK_ADDED 메시지를 연결된 NVP들에게 Broadcast.
	// VP들은 신규 추가된 블록의 execution(컨센서스 중 실행)에 참여했기 때문에 이미 이 블록을 알고 있음.
	// 즉, VP들은 네트워트 블록과 현재의 블록을 비교할 수 있다.
	msg := &pb.Message{Type: pb.Message_SYNC_BLOCK_ADDED,
		Payload: data, Timestamp: util.CreateUtcTimestamp()}
	if errs := i.stack.Broadcast(msg, pb.PeerEndpoint_NON_VALIDATOR); nil != errs {
		return fmt.Errorf("Failed to broadcast with errors: %v", errs)
	}
	return nil
}

// Executed is called whenever Execute completes, no-op for noops as it uses the legacy synchronous api
func (i *Noops) Executed(tag interface{}) {
	// Never called
}

// Committed is called whenever Commit completes, no-op for noops as it uses the legacy synchronous api
func (i *Noops) Committed(tag interface{}, target *pb.BlockchainInfo) {
	// Never called
}

// RolledBack is called whenever a Rollback completes, no-op for noops as it uses the legacy synchronous api
func (i *Noops) RolledBack(tag interface{}) {
	// Never called
}

// StatedUpdates is called when state transfer completes, if target is nil, this indicates a failure and a new target should be supplied, no-op for noops as it uses the legacy synchronous api
func (i *Noops) StateUpdated(tag interface{}, target *pb.BlockchainInfo) {
	// Never called
}
