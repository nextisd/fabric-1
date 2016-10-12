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

//blockchain과 global state를 저장하는 ledger를 구현함
package ledger

import (
	"bytes"
	"fmt"
	"reflect"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/core/db"
	"github.com/hyperledger/fabric/core/ledger/statemgmt"
	"github.com/hyperledger/fabric/core/ledger/statemgmt/state"
	"github.com/hyperledger/fabric/events/producer"
	"github.com/op/go-logging"
	"github.com/tecbot/gorocksdb"

	"github.com/hyperledger/fabric/protos"
	"golang.org/x/net/context"
)

var ledgerLogger = logging.MustGetLogger("ledger")

//ErrorType represents the type of a ledger error
type ErrorType string

const (
	//ErrorType 정의

	//ErrorTypeInvalidArgument used to indicate the invalid input to ledger method
	//잘못된 입력 인자값
	ErrorTypeInvalidArgument = ErrorType("InvalidArgument")

	//ErrorTypeOutOfBounds used to indicate that a request is out of bounds
	//요청한도초과
	ErrorTypeOutOfBounds = ErrorType("OutOfBounds")

	//ErrorTypeResourceNotFound used to indicate if a resource is not found
	//리소스부족
	ErrorTypeResourceNotFound = ErrorType("ResourceNotFound")

	//ErrorTypeBlockNotFound used to indicate if a block is not found when looked up by it's hash
	//hash값으로 블록이 검색되지 않을때
	ErrorTypeBlockNotFound = ErrorType("ErrorTypeBlockNotFound")
)

//Error can be used for throwing an error from ledger code.
//
//Error 구조체 : ledger code로 부터 에러 핸들링
type Error struct {
	errType ErrorType
	msg     string
}

func (ledgerError *Error) Error() string {
	return fmt.Sprintf("LedgerError - %s: %s", ledgerError.errType, ledgerError.msg)
}

//Type returns the type of the error
//
//  Type() : 에러 타입 반환
func (ledgerError *Error) Type() ErrorType {
	return ledgerError.errType
}

func newLedgerError(errType ErrorType, msg string) *Error {
	return &Error{errType, msg}
}

var (
	// ErrOutOfBounds is returned if a request is out of bounds
	ErrOutOfBounds = newLedgerError(ErrorTypeOutOfBounds, "ledger: out of bounds")

	// ErrResourceNotFound is returned if a resource is not found
	ErrResourceNotFound = newLedgerError(ErrorTypeResourceNotFound, "ledger: resource not found")
)

// Ledger - the struct for openchain ledger
//
// Ledger - openchain ledger 구조체
type Ledger struct {
	blockchain *blockchain
	state      *state.State
	currentID  interface{}
}

var ledger *Ledger
var ledgerError error

// once : 하나의 동작만 수행하는 객체(mutex)
var once sync.Once

// GetLedger - gives a reference to a 'singleton' ledger
//
//GetLedger() : 'singleton' ledger 객체 레퍼런스 리턴
func GetLedger() (*Ledger, error) {
	once.Do(func() {
		ledger, ledgerError = GetNewLedger()
	})
	return ledger, ledgerError
}

// GetNewLedger - gives a reference to a new ledger TODO need better approach
//
// GetNewLedger() : 신규 ledger 레퍼런스 주소 리턴, TODO 호출 방법 개선 필요
func GetNewLedger() (*Ledger, error) {
	blockchain, err := newBlockchain()
	if err != nil {
		return nil, err
	}

	state := state.NewState()
	return &Ledger{blockchain, state, nil}, nil
}

/////////////////// Transaction-batch related methods ///////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

// BeginTxBatch - gets invoked when next round of transaction-batch execution begins
//
// BeginTxBatch() : 트랜잭션 일괄처리(transaction-batch) 다음 라운드가 시작될때 호출됨(invoked)
func (ledger *Ledger) BeginTxBatch(id interface{}) error {
	err := ledger.checkValidIDBegin()
	if err != nil {
		return err
	}
	ledger.currentID = id
	return nil
}

// GetTXBatchPreviewBlockInfo returns a preview block info that will
// contain the same information as GetBlockchainInfo will return after
// ledger.CommitTxBatch is called with the same parameters. If the
// state is modified by a transaction between these two calls, the
// contained hash will be different.
//
// GetTXBatchPreviewBlockInfo() :
// ledger.CommitTxBatch()가 실행된 이후 GetBlockchainInfo() 리턴값과 동일한 '이전 블록 정보'를 리턴.
// 두개의 call 사이에 state 변경이 있을 경우는 리턴될 hash값들은 다를 수 있음
func (ledger *Ledger) GetTXBatchPreviewBlockInfo(id interface{},
	transactions []*protos.Transaction, metadata []byte) (*protos.BlockchainInfo, error) {
	err := ledger.checkValidIDCommitORRollback(id)
	if err != nil {
		return nil, err
	}
	// stateHash : stateDelta가 변경되었을 경우에 new state hash값을 리턴함
	stateHash, err := ledger.state.GetHash()
	if err != nil {
		return nil, err
	}
	block := ledger.blockchain.buildBlock(protos.NewBlock(transactions, metadata), stateHash)
	info := ledger.blockchain.getBlockchainInfoForBlock(ledger.blockchain.getSize()+1, block)
	return info, nil
}

// CommitTxBatch - gets invoked when the current transaction-batch needs to be committed
// This function returns successfully iff the transactions details and state changes (that
// may have happened during execution of this transaction-batch) have been committed to permanent storage
//
// CommitTxBatch() : transaction-batch가 commit될 필요가 있을때 호출됨.
// 트랜잭션 처리, state change가 정상적으로 스토리지에 commit 되었을때 정상 리턴됨.
func (ledger *Ledger) CommitTxBatch(id interface{}, transactions []*protos.Transaction, transactionResults []*protos.TransactionResult, metadata []byte) error {
	err := ledger.checkValidIDCommitORRollback(id)
	if err != nil {
		return err
	}

	stateHash, err := ledger.state.GetHash()
	if err != nil {
		ledger.resetForNextTxGroup(false)
		ledger.blockchain.blockPersistenceStatus(false)
		return err
	}

	// rocksDB에 저장해서 작업, commit 종료 후 delete?
	writeBatch := gorocksdb.NewWriteBatch()
	defer writeBatch.Destroy()
	block := protos.NewBlock(transactions, metadata)

	ccEvents := []*protos.ChaincodeEvent{}

	if transactionResults != nil {
		ccEvents = make([]*protos.ChaincodeEvent, len(transactionResults))
		for i := 0; i < len(transactionResults); i++ {
			if transactionResults[i].ChaincodeEvent != nil {
				ccEvents[i] = transactionResults[i].ChaincodeEvent
			} else {
				//We need the index so we can map the chaincode
				//event to the transaction that generated it.
				//Hence need an entry for cc event even if one
				//wasn't generated for the transaction. We cannot
				//use a nil cc event as protobuf does not like
				//elements of a repeated array to be nil.
				//
				//We should discard empty events without chaincode
				//ID when sending out events.
				//
				// chaincode event : [ChaincodeID, TxID, EventName, Payload]
				// 트랜잭션에 chaincode event를 매핑 할 수 있도록 인덱스가 필요.
				// 따라서, chaincode event에 대한 entry point가 필요.
				// nil 체인코드 이벤트는 사용할 수 없음.(e.g. protobuf도 반복될 배열을 nill로 채우지 않음)
				//
				// 이벤트를 보낼때 ChaincodeID가 없는 빈 이벤트는 폐기해야함.
				ccEvents[i] = &protos.ChaincodeEvent{}
			}
		}
	}

	//store chaincode events directly in NonHashData. This will likely change in New Consensus where we can move them to Transaction
	//
	//chaincode event를 NonHashData에 직접 저장.
	//새로운 컨센서스에 반영될 변경사항.
	block.NonHashData = &protos.NonHashData{ChaincodeEvents: ccEvents}
	newBlockNumber, err := ledger.blockchain.addPersistenceChangesForNewBlock(context.TODO(), block, stateHash, writeBatch)
	if err != nil {
		ledger.resetForNextTxGroup(false)
		ledger.blockchain.blockPersistenceStatus(false)
		return err
	}
	// 신규 블록에 key-value 쌍들을 반영. 해당블록 컬럼패밀리에 key-value 큐잉.
	ledger.state.AddChangesForPersistence(newBlockNumber, writeBatch)
	opt := gorocksdb.NewDefaultWriteOptions()
	defer opt.Destroy()
	// DB에 Batch-Write
	dbErr := db.GetDBHandle().DB.Write(opt, writeBatch)
	if dbErr != nil {
		ledger.resetForNextTxGroup(false)
		ledger.blockchain.blockPersistenceStatus(false)
		return dbErr
	}

	ledger.resetForNextTxGroup(true)
	ledger.blockchain.blockPersistenceStatus(true)

	// 블록생성 이벤트 전송
	sendProducerBlockEvent(block)

	//send chaincode events from transaction results
	//
	//트랜잭션 처리 결과를 전송 to consumers : producer.send(ChaincodeEvent)
	sendChaincodeEvents(transactionResults)

	if len(transactionResults) != 0 {
		ledgerLogger.Debug("There were some erroneous transactions. We need to send a 'TX rejected' message here.")
	}
	return nil
}

// RollbackTxBatch - Discards all the state changes that may have taken place during the execution of
// current transaction-batch
//
// RollbackTxBatch() : transaction-batch 실행중 일어났을수 있는 모든 상태 변경분을 롤백.
func (ledger *Ledger) RollbackTxBatch(id interface{}) error {
	ledgerLogger.Debugf("RollbackTxBatch for id = [%s]", id)
	err := ledger.checkValidIDCommitORRollback(id)
	if err != nil {
		return err
	}
	ledger.resetForNextTxGroup(false)
	return nil
}

// TxBegin - Marks the begin of a new transaction in the ongoing batch
//
// TxBegin() : 진행중인 batch의 새로운 트랜잭션의 시작 마킹, state.currentID = txID 처리.
// 트랜잭션이 이미 실행중일때 호출할 경우 panic 발생
func (ledger *Ledger) TxBegin(txID string) {
	ledger.state.TxBegin(txID)
}

// TxFinished - Marks the finish of the on-going transaction.
// If txSuccessful is false, the state changes made by the transaction are discarded
//
// TxFinished() : 진행중인 트랜잭션의 종료 마킹.
//  1.state.currentTxStateDelta = statemgmt.NewStateDelta()
//  2.state.currentTxID = ""
func (ledger *Ledger) TxFinished(txID string, txSuccessful bool) {
	ledger.state.TxFinish(txID, txSuccessful)
}

/////////////////// world-state related methods /////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

// GetTempStateHash - Computes state hash by taking into account the state changes that may have taken
// place during the execution of current transaction-batch
//
// GetTempStateHash() : 현재 transaction-batch를 처리하는 동안 상태 변화를 포함한 state hash값을 계산.
func (ledger *Ledger) GetTempStateHash() ([]byte, error) {
	return ledger.state.GetHash()
}

// GetTempStateHashWithTxDeltaStateHashes - In addition to the state hash (as defined in method GetTempStateHash),
// this method returns a map [txUuid of Tx --> cryptoHash(stateChangesMadeByTx)]
// Only successful txs appear in this map
//
// GetTempStateHashWithTxDeltaStateHashes() :
//  GetTempStateHash()에서 정의된 state hash값에 상태변경 map(txUuid of Tx)의 해쉬값을 추가로 리턴함
//		1. state.stateDelta.ApplyChanges(state.currentTxStateDelta)
//		2. state.txStateDeltaHash[txID] = state.currentTxStateDelta.ComputeCryptoHash()
func (ledger *Ledger) GetTempStateHashWithTxDeltaStateHashes() ([]byte, map[string][]byte, error) {
	stateHash, err := ledger.state.GetHash()
	return stateHash, ledger.state.GetTxStateDeltaHash(), err
}

// GetState get state for chaincodeID and key. If committed is false, this first looks in memory
// and if missing, pulls from db.  If committed is true, this pulls from the db only.
//
// GetState() : ChaincodeID/key로 state 조회.
//  @param committed(false) : memory -> db 순서로 검색.
//  @param committed(true)  : db 에서만 가져옴.
func (ledger *Ledger) GetState(chaincodeID string, key string, committed bool) ([]byte, error) {
	return ledger.state.Get(chaincodeID, key, committed)
}

// GetStateRangeScanIterator returns an iterator to get all the keys (and values) between startKey and endKey
// (assuming lexical order of the keys) for a chaincodeID.
// If committed is true, the key-values are retrieved only from the db. If committed is false, the results from db
// are mergerd with the results in memory (giving preference to in-memory data)
// The key-values in the returned iterator are not guaranteed to be in any specific order
//
// GetStateRangeScanIterator() : chaincodeID에 해당하는 startKey~endKey 사이의 모든 Key-Value를 사전순으로 리턴함(iterator)
// @param committed(true) : key-value는 DB에서만 가져옴
// @param committed(false): DB로부터 가져온 결과를 memory에서 가져온 결과와 통합(in-memory데이터에 우선권을 줌)
// 리턴된 interator의 key-value는 특정한 순서를 보장하지는 않음.
func (ledger *Ledger) GetStateRangeScanIterator(chaincodeID string, startKey string, endKey string, committed bool) (statemgmt.RangeScanIterator, error) {
	return ledger.state.GetRangeScanIterator(chaincodeID, startKey, endKey, committed)
}

// SetState sets state to given value for chaincodeID and key. Does not immideatly writes to DB
//
// SetState() : chaincodeID와 key에 대해서 value를 설정함. DB에 바로 쓰지는 않음.
func (ledger *Ledger) SetState(chaincodeID string, key string, value []byte) error {
	if key == "" || value == nil {
		return newLedgerError(ErrorTypeInvalidArgument,
			fmt.Sprintf("An empty string key or a nil value is not supported. Method invoked with key='%s', value='%#v'", key, value))
	}
	return ledger.state.Set(chaincodeID, key, value)
}

// DeleteState tracks the deletion of state for chaincodeID and key. Does not immediately writes to DB
//
// DeleteState() : chaincodeID와 key에 해당하는 value(state)의 삭제처리. DB에 바로 쓰지는 않음.
func (ledger *Ledger) DeleteState(chaincodeID string, key string) error {
	return ledger.state.Delete(chaincodeID, key)
}

// CopyState copies all the key-values from sourceChaincodeID to destChaincodeID
//
// CopyState() : 모든 key-value들을 sourceChaincodeID에서 destChaincodeID로 복사
func (ledger *Ledger) CopyState(sourceChaincodeID string, destChaincodeID string) error {
	return ledger.state.CopyState(sourceChaincodeID, destChaincodeID)
}

// GetStateMultipleKeys returns the values for the multiple keys.
// This method is mainly to amortize the cost of grpc communication between chaincode shim peer
//
// GetStateMultipleKeys() : 여러개의 key에 대한 value를 리턴.
// chaincode와 shim peer간의 grpc 처리 부하를 줄일 수 있음.
func (ledger *Ledger) GetStateMultipleKeys(chaincodeID string, keys []string, committed bool) ([][]byte, error) {
	return ledger.state.GetMultipleKeys(chaincodeID, keys, committed)
}

// SetStateMultipleKeys sets the values for the multiple keys.
// This method is mainly to amortize the cost of grpc communication between chaincode shim peer
//
// SetStateMultipleKeys() : 여러개의 key에 대한 value를 설정.
// chaincode와 shim peer간의 grpc 처리 부하를 줄일 수 있음.
func (ledger *Ledger) SetStateMultipleKeys(chaincodeID string, kvs map[string][]byte) error {
	return ledger.state.SetMultipleKeys(chaincodeID, kvs)
}

// GetStateSnapshot returns a point-in-time view of the global state for the current block. This
// should be used when transferring the state from one peer to another peer. You must call
// stateSnapshot.Release() once you are done with the snapshot to free up resources.
//
// GetStateSnapshot() : 현재 블록의 global state에 대한 스냅샷을 리턴.
// 피어에서 다른 피어로 state를 전송할때 사용해야함.
// 실행완료 후 스냅샷에 대한 자원 반환을 위해 stateSnapshot.Release()를 꼭 호출해야함!
func (ledger *Ledger) GetStateSnapshot() (*state.StateSnapshot, error) {
	dbSnapshot := db.GetDBHandle().GetSnapshot()
	blockHeight, err := fetchBlockchainSizeFromSnapshot(dbSnapshot)
	if err != nil {
		dbSnapshot.Release()
		return nil, err
	}
	if 0 == blockHeight {
		dbSnapshot.Release()
		return nil, fmt.Errorf("Blockchain has no blocks, cannot determine block number")
	}
	return ledger.state.GetSnapshot(blockHeight-1, dbSnapshot)
}

// GetStateDelta will return the state delta for the specified block if
// available.  If not available because it has been discarded, returns nil,nil.
//
// GetStateDelta() : 특정한 블록의 state delta를 리턴.
// 처리가 불가한 경우는 nil,nil이 리턴됨.
func (ledger *Ledger) GetStateDelta(blockNumber uint64) (*statemgmt.StateDelta, error) {
	if blockNumber >= ledger.GetBlockchainSize() {
		return nil, ErrOutOfBounds
	}
	return ledger.state.FetchStateDeltaFromDB(blockNumber)
}

// ApplyStateDelta applies a state delta to the current state. This is an
// in memory change only. You must call ledger.CommitStateDelta to persist
// the change to the DB.
// This should only be used as part of state synchronization. State deltas
// can be retrieved from another peer though the Ledger.GetStateDelta function
// or by creating state deltas with keys retrieved from
// Ledger.GetStateSnapshot(). For an example, see TestSetRawState in
// ledger_test.go
// Note that there is no order checking in this function and it is up to
// the caller to ensure that deltas are applied in the correct order.
// For example, if you are currently at block 8 and call this function
// with a delta retrieved from Ledger.GetStateDelta(10), you would now
// be in a bad state because you did not apply the delta for block 9.
// It's possible to roll the state forwards or backwards using
// stateDelta.RollBackwards. By default, a delta retrieved for block 3 can
// be used to roll forwards from state at block 2 to state at block 3. If
// stateDelta.RollBackwards=false, the delta retrieved for block 3 can be
// used to roll backwards from the state at block 3 to the state at block 2.
//
// ApplyStateDelta() : 현재의 state에 state delta를 적용함.
// in-memory에만 변경이 되며, 영구적인 반영을 위해서는 ledger.CommitStateDelta를 호출해야함.
// 상태 동기화(state synchronization) 처리시에만 사용되어야 하는 함수임.
//
// State delta : e.g. ledger_test.go의 TestSetRawState() 참고
//  1.다른 피어에서 Ledger.GetStateDelta를 실행한 결과를 통해서 얻을 수 있고
//  2.Ledger.GetStateSnapshot()에서 리턴된 key를 기반으로 state delta를 생성
// 이 함수에서는 order check가 없으며 호출자가 delta들이 적절한 순서로 적용되었는지를 확인해야 함
//
// 예를들면, 만약 당신이 현재 block8 에 있을때,
// Ledger.GetStateDelta(10)에서 리턴된 delta를 인자로 사용해서 이 함수를 호출하였을 경우,
// 당신은 block9에 대한 delta를 apply 하지 않았기 때문에 bad state가 된다.
//
// stateDelta.RollBackward를 통해 state를 roll foward/backward 하는게 가능함.
// 기본적으로, block3에서 가져온 delta는 block2에서 block3로 roll forwards할때 사용할 수 있다.
//
// 만약, stateDelta.RollBackwards=false라면 block3에서 가져온 delta는 block3에서 block2로 roll backwards시 사용 할수 있다.
func (ledger *Ledger) ApplyStateDelta(id interface{}, delta *statemgmt.StateDelta) error {
	err := ledger.checkValidIDBegin()
	if err != nil {
		return err
	}
	ledger.currentID = id
	ledger.state.ApplyStateDelta(delta)
	return nil
}

// CommitStateDelta will commit the state delta passed to ledger.ApplyStateDelta
// to the DB
//
// CommitStateDelta() : state delta를 ledger.ApplyStateDelta에서 DB로 commit 처리
func (ledger *Ledger) CommitStateDelta(id interface{}) error {
	err := ledger.checkValidIDCommitORRollback(id)
	if err != nil {
		return err
	}
	defer ledger.resetForNextTxGroup(true)
	return ledger.state.CommitStateDelta()
}

// RollbackStateDelta will discard the state delta passed
// to ledger.ApplyStateDelta
//
// RollbackStateDelta() : state delta 롤백
func (ledger *Ledger) RollbackStateDelta(id interface{}) error {
	err := ledger.checkValidIDCommitORRollback(id)
	if err != nil {
		return err
	}
	ledger.resetForNextTxGroup(false)
	return nil
}

// DeleteALLStateKeysAndValues deletes all keys and values from the state.
// This is generally only used during state synchronization when creating a
// new state from a snapshot.
//
// DeleteALLStateKeysAndValues() : state의 모든 key-value를 삭제.
// snapshot으로 부터 new state를 생성할때 state synchronization을 할때만 사용하는게 일반적임
func (ledger *Ledger) DeleteALLStateKeysAndValues() error {
	return ledger.state.DeleteState()
}

/////////////////// blockchain related methods /////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

// GetBlockchainInfo returns information about the blockchain ledger such as
// height, current block hash, and previous block hash.
//
// GetBlockchainInfo() : blockchain ledger 정보 조회(height, current/previous block hash,...)
func (ledger *Ledger) GetBlockchainInfo() (*protos.BlockchainInfo, error) {
	return ledger.blockchain.getBlockchainInfo()
}

// GetBlockByNumber return block given the number of the block on blockchain.
// Lowest block on chain is block number zero
//
// GetBlockByNumber() : 블록 번호(높이)에 해당하는 블록 리턴
func (ledger *Ledger) GetBlockByNumber(blockNumber uint64) (*protos.Block, error) {
	if blockNumber >= ledger.GetBlockchainSize() {
		return nil, ErrOutOfBounds
	}
	return ledger.blockchain.getBlock(blockNumber)
}

// GetBlockchainSize returns number of blocks in blockchain
// GetBlockchainSize() : 총 블록개수 리턴
func (ledger *Ledger) GetBlockchainSize() uint64 {
	return ledger.blockchain.getSize()
}

// GetTransactionByID return transaction by it's txId
//
// GetTransactionByID() : txID에 해당하는 트랜잭션 리턴
func (ledger *Ledger) GetTransactionByID(txID string) (*protos.Transaction, error) {
	return ledger.blockchain.getTransactionByID(txID)
}

// PutRawBlock puts a raw block on the chain. This function should only be
// used for synchronization between peers.
//
// PutRawBlock() : raw block을 블록체인에 추가. 피어간 동기화시에만 사용해야함!
func (ledger *Ledger) PutRawBlock(block *protos.Block, blockNumber uint64) error {
	err := ledger.blockchain.persistRawBlock(block, blockNumber)
	if err != nil {
		return err
	}
	sendProducerBlockEvent(block)
	return nil
}

// VerifyChain will verify the integrity of the blockchain. This is accomplished
// by ensuring that the previous block hash stored in each block matches
// the actual hash of the previous block in the chain. The return value is the
// block number of lowest block in the range which can be verified as valid.
// The first block is assumed to be valid, and an error is only returned if the
// first block does not exist, or some other sort of irrecoverable ledger error
// such as the first block failing to hash is encountered.
// For example, if VerifyChain(0, 99) is called and previous hash values stored
// in blocks 8, 32, and 42 do not match the actual hashes of respective previous
// block 42 would be the return value from this function.
// highBlock is the high block in the chain to include in verification. If you
// wish to verify the entire chain, use ledger.GetBlockchainSize() - 1.
// lowBlock is the low block in the chain to include in verification. If
// you wish to verify the entire chain, use 0 for the genesis block.
//
// VerifyChain() : blockchain의 무결성 검증시 사용.
//
// 블록내부의 이전블록해쉬값이 실제 블록체인상의 이전 블록의 해쉬값과 동일한지를 검증함
// VerifyChain(0,99)와 같이 범위를 지정할수 있고 만약, 8, 32, 42 블록에서 이전블록해쉬값이 불일치 할경우,
// 42블록을 에러로 리턴함.
// @param highBlock : 시작블록, 모든 블록을 검증하려면 ledger.GetBlockchainSize()-1 을 세팅.
// @param lowBlock  : 종료블록, 모든 블록을 검증하려면 0을 세팅(genesis block)
func (ledger *Ledger) VerifyChain(highBlock, lowBlock uint64) (uint64, error) {
	if highBlock >= ledger.GetBlockchainSize() {
		return highBlock, ErrOutOfBounds
	}
	if highBlock < lowBlock {
		return lowBlock, ErrOutOfBounds
	}

	currentBlock, err := ledger.GetBlockByNumber(highBlock)
	if err != nil {
		return highBlock, fmt.Errorf("Error fetching block %d.", highBlock)
	}
	if currentBlock == nil {
		return highBlock, fmt.Errorf("Block %d is nil.", highBlock)
	}

	for i := highBlock; i > lowBlock; i-- {
		previousBlock, err := ledger.GetBlockByNumber(i - 1)
		if err != nil {
			return i, nil
		}
		if previousBlock == nil {
			return i, nil
		}
		previousBlockHash, err := previousBlock.GetHash()
		if err != nil {
			return i, nil
		}
		if bytes.Compare(previousBlockHash, currentBlock.PreviousBlockHash) != 0 {
			return i, nil
		}
		currentBlock = previousBlock
	}

	return lowBlock, nil
}

func (ledger *Ledger) checkValidIDBegin() error {
	if ledger.currentID != nil {
		return fmt.Errorf("Another TxGroup [%s] already in-progress", ledger.currentID)
	}
	return nil
}

func (ledger *Ledger) checkValidIDCommitORRollback(id interface{}) error {
	if !reflect.DeepEqual(ledger.currentID, id) {
		return fmt.Errorf("Another TxGroup [%s] already in-progress", ledger.currentID)
	}
	return nil
}

func (ledger *Ledger) resetForNextTxGroup(txCommited bool) {
	ledgerLogger.Debug("resetting ledger state for next transaction batch")
	ledger.currentID = nil
	ledger.state.ClearInMemoryChanges(txCommited)
}

// block.sendProducerBlockEvent() : 블록생성 이벤트를 전송
func sendProducerBlockEvent(block *protos.Block) {

	// Remove payload from deploy transactions. This is done to make block
	// events more lightweight as the payload for these types of transactions
	// can be very large.
	//
	// deploy transacation에서 payload를 제거.
	// block event를 경량화 하기 위한 목적임(해당 유형의 트랜잭션의 payload는 굉장히 커질 수도 있음)
	blockTransactions := block.GetTransactions()
	for _, transaction := range blockTransactions {
		if transaction.Type == protos.Transaction_CHAINCODE_DEPLOY {
			deploymentSpec := &protos.ChaincodeDeploymentSpec{}
			err := proto.Unmarshal(transaction.Payload, deploymentSpec)
			if err != nil {
				ledgerLogger.Errorf("Error unmarshalling deployment transaction for block event: %s", err)
				continue
			}
			deploymentSpec.CodePackage = nil
			deploymentSpecBytes, err := proto.Marshal(deploymentSpec)
			if err != nil {
				ledgerLogger.Errorf("Error marshalling deployment transaction for block event: %s", err)
				continue
			}
			transaction.Payload = deploymentSpecBytes
		}
	}

	producer.Send(producer.CreateBlockEvent(block))
}

//send chaincode events created by transactions
//
// sendChaincodEvents() : 트랜잭션으로 부터 생성된 chaincode event 전송.
func sendChaincodeEvents(trs []*protos.TransactionResult) {
	if trs != nil {
		for _, tr := range trs {
			//we store empty chaincode events in the protobuf repeated array to make protobuf happy.
			//when we replay off a block ignore empty events
			//
			//empty chaincode event는 전송 안함.
			if tr.ChaincodeEvent != nil && tr.ChaincodeEvent.ChaincodeID != "" {
				producer.Send(producer.CreateChaincodeEvent(tr.ChaincodeEvent))
			}
		}
	}
}
