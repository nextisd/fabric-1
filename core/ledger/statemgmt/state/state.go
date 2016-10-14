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

package state

import (
	"encoding/binary"
	"fmt"

	"github.com/hyperledger/fabric/core/db"
	"github.com/hyperledger/fabric/core/ledger/statemgmt"
	"github.com/hyperledger/fabric/core/ledger/statemgmt/buckettree"
	"github.com/hyperledger/fabric/core/ledger/statemgmt/raw"
	"github.com/hyperledger/fabric/core/ledger/statemgmt/trie"
	"github.com/op/go-logging"
	"github.com/tecbot/gorocksdb"
)

var logger = logging.MustGetLogger("state")

const defaultStateImpl = "buckettree"

var stateImpl statemgmt.HashableState

type stateImplType string

const (
	buckettreeType stateImplType = "buckettree"
	trieType       stateImplType = "trie"
	rawType        stateImplType = "raw"
)

// State structure for maintaining world state.
// This encapsulates a particular implementation for managing the state persistence
// This is not thread safe
//
// State 구조체 : world state 처리를 위해 사용됨.
// state 지속성을 관리 하기 위함.
// thread-safe 하지 않음(락 처리 없음?)
type State struct {
	stateImpl statemgmt.HashableState // State management 인터페이스

	// stateDelta : ChaincodeStateDeltas 맵(ChaincodeID, UpdatedKVs[Value, PreviousValue]맵) , Rollbackwards bool
	stateDelta            *statemgmt.StateDelta
	currentTxStateDelta   *statemgmt.StateDelta
	currentTxID           string
	txStateDeltaHash      map[string][]byte
	updateStateImpl       bool
	historyStateDeltaSize uint64
}

// NewState constructs a new State. This Initializes encapsulated state implementation
//
// NewState() : 신규 state 생성 및 초기화.
func NewState() *State {
	// github.com/nextisd/kksl/core/ledger/statemgmt/state/config.go - loadConfig()
	initConfig()
	logger.Infof("Initializing state implementation [%s]", stateImplName)

	// State Management는 현재 3가지 유형으로 구현 가능
	// 1. buckettreeType : 키 값이 범위를 n개의 버킷으로 나누어 저장?
	// 2. trieType       : 이진검색트리가 아님, 특정 노드의 후손들은 그 노드와 동일한 prefix를 가짐.
	//						http://m.blog.naver.com/javaking75/140211950640 참고
	// 3. rawType        : 자료구조 없이 그냥 KVs store 처리??
	switch stateImplName {
	case buckettreeType:
		stateImpl = buckettree.NewStateImpl()
	case trieType:
		stateImpl = trie.NewStateImpl()
	case rawType:
		stateImpl = raw.NewStateImpl()
	default:
		panic("Should not reach here. Configs should have checked for the stateImplName being a valid names ")
	}
	err := stateImpl.Initialize(stateImplConfigs)
	if err != nil {
		panic(fmt.Errorf("Error during initialization of state implementation: %s", err))
	}
	return &State{stateImpl, statemgmt.NewStateDelta(), statemgmt.NewStateDelta(), "", make(map[string][]byte),
		false, uint64(deltaHistorySize)}
}

// TxBegin marks begin of a new tx. If a tx is already in progress, this call panics
//
// state.TxBegin() : 신규 tx 시작 마킹(state.currentTxID = @txID), 이미 tx가 처리중이면 panic 발생.
func (state *State) TxBegin(txID string) {
	logger.Debugf("txBegin() for txId [%s]", txID)
	if state.txInProgress() {
		panic(fmt.Errorf("A tx [%s] is already in progress. Received call for begin of another tx [%s]", state.currentTxID, txID))
	}
	state.currentTxID = txID
}

// TxFinish marks the completion of on-going tx. If txID is not same as of the on-going tx, this call panics
//
// state.TxFinish() : tx 종료 마킹,  @txID가 처리중이었던 tx가 아니면 panic 발생
// stateDelta 최종 반영
func (state *State) TxFinish(txID string, txSuccessful bool) {
	logger.Debugf("txFinish() for txId [%s], txSuccessful=[%t]", txID, txSuccessful)
	if state.currentTxID != txID {
		panic(fmt.Errorf("Different txId in tx-begin [%s] and tx-finish [%s]", state.currentTxID, txID))
	}
	if txSuccessful {
		if !state.currentTxStateDelta.IsEmpty() {
			logger.Debugf("txFinish() for txId [%s] merging state changes", txID)
			// 현재 txID에 대한 stateDelta가 존재할 경우, merge처리
			state.stateDelta.ApplyChanges(state.currentTxStateDelta)
			state.txStateDeltaHash[txID] = state.currentTxStateDelta.ComputeCryptoHash()
			state.updateStateImpl = true
		} else {
			state.txStateDeltaHash[txID] = nil
		}
	}
	// state.curretTx~ 초기화
	state.currentTxStateDelta = statemgmt.NewStateDelta()
	state.currentTxID = ""
}

// state.txInProgress() : state.currentID가 세팅되어 있으면 tx 처리중.
func (state *State) txInProgress() bool {
	return state.currentTxID != ""
}

// Get returns state for chaincodeID and key. If committed is false, this first looks in memory and if missing,
// pulls from db. If committed is true, this pulls from the db only.
//
// state.Get() : @chaincodeID와 @key에 해당하는 state를 리턴.
//  @param committed(false) : memory -> db 순서로 검색.
//  @param committed(true)  : db 에서만 가져옴.
func (state *State) Get(chaincodeID string, key string, committed bool) ([]byte, error) {
	if !committed {
		valueHolder := state.currentTxStateDelta.Get(chaincodeID, key)
		if valueHolder != nil {
			return valueHolder.GetValue(), nil
		}
		valueHolder = state.stateDelta.Get(chaincodeID, key)
		if valueHolder != nil {
			return valueHolder.GetValue(), nil
		}
	}
	return state.stateImpl.Get(chaincodeID, key)
}

// GetRangeScanIterator returns an iterator to get all the keys (and values) between startKey and endKey
// (assuming lexical order of the keys) for a chaincodeID.
//
// state.GetRangeScanIterator() : chaincodeID에 해당하는 startKey~endKey 사이의 모든 Key-Value를 사전순으로 리턴함(iterator)
func (state *State) GetRangeScanIterator(chaincodeID string, startKey string, endKey string, committed bool) (statemgmt.RangeScanIterator, error) {
	stateImplItr, err := state.stateImpl.GetRangeScanIterator(chaincodeID, startKey, endKey)
	if err != nil {
		return nil, err
	}

	if committed {
		return stateImplItr, nil
	}
	return newCompositeRangeScanIterator(
		statemgmt.NewStateDeltaRangeScanIterator(state.currentTxStateDelta, chaincodeID, startKey, endKey),
		statemgmt.NewStateDeltaRangeScanIterator(state.stateDelta, chaincodeID, startKey, endKey),
		stateImplItr), nil
}

// Set sets state to given value for chaincodeID and key. Does not immediately writes to DB
//
// state.Set() : chaincodeID와 key에 대해서 value를 설정함. DB에 바로 쓰지는 않음.
func (state *State) Set(chaincodeID string, key string, value []byte) error {
	logger.Debugf("set() chaincodeID=[%s], key=[%s], value=[%#v]", chaincodeID, key, value)
	if !state.txInProgress() {
		panic("State can be changed only in context of a tx.")
	}

	// Check if a previous value is already set in the state delta
	//
	// stateDelta에 'previous value'가 이미 세팅되었는지 체크
	if state.currentTxStateDelta.IsUpdatedValueSet(chaincodeID, key) {
		// No need to bother looking up the previous value as we will not
		// set it again. Just pass nil
		//
		// if 세팅되어 있다면, 'previous value'를 다시 설정할 필요 없음.
		state.currentTxStateDelta.Set(chaincodeID, key, value, nil)
	} else {
		// Need to lookup the previous value
		//
		// if 세팅 안되어 있다면, 'previous value'를 설정해야함
		previousValue, err := state.Get(chaincodeID, key, true)
		if err != nil {
			return err
		}
		state.currentTxStateDelta.Set(chaincodeID, key, value, previousValue)
	}

	return nil
}

// Delete tracks the deletion of state for chaincodeID and key. Does not immediately writes to DB
//
// state.Delete() : chaincodeID와 key에 해당하는 value(state)의 삭제처리. DB에 바로 쓰지는 않음.
func (state *State) Delete(chaincodeID string, key string) error {
	logger.Debugf("delete() chaincodeID=[%s], key=[%s]", chaincodeID, key)

	// tx 처리중이면 panic 발생
	if !state.txInProgress() {
		panic("State can be changed only in context of a tx.")
	}

	// Check if a previous value is already set in the state delta
	//
	// stateDelta에 'previous value'가 이미 세팅되었는지 체크
	if state.currentTxStateDelta.IsUpdatedValueSet(chaincodeID, key) {
		// No need to bother looking up the previous value as we will not
		// set it again. Just pass nil
		state.currentTxStateDelta.Delete(chaincodeID, key, nil)
	} else {
		// Need to lookup the previous value
		previousValue, err := state.Get(chaincodeID, key, true)
		if err != nil {
			return err
		}
		state.currentTxStateDelta.Delete(chaincodeID, key, previousValue)
	}

	return nil
}

// CopyState copies all the key-values from sourceChaincodeID to destChaincodeID
//
// state.CopyState() : 모든 key-value들을 @sourceChaincodeID에서 @destChaincodeID로 복사
func (state *State) CopyState(sourceChaincodeID string, destChaincodeID string) error {
	itr, err := state.GetRangeScanIterator(sourceChaincodeID, "", "", true)
	defer itr.Close()
	if err != nil {
		return err
	}
	for itr.Next() {
		k, v := itr.GetKeyValue()
		err := state.Set(destChaincodeID, k, v)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetMultipleKeys returns the values for the multiple keys.
// state.GetMultipleKeys() : 여러개의 key에 대한 value를 리턴.
func (state *State) GetMultipleKeys(chaincodeID string, keys []string, committed bool) ([][]byte, error) {
	var values [][]byte
	for _, k := range keys {
		v, err := state.Get(chaincodeID, k, committed)
		if err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, nil
}

// SetMultipleKeys sets the values for the multiple keys.
// state.SetMultipleKeys() : 여러개의 key에 대한 value를 설정.
func (state *State) SetMultipleKeys(chaincodeID string, kvs map[string][]byte) error {
	for k, v := range kvs {
		err := state.Set(chaincodeID, k, v)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetHash computes new state hash if the stateDelta is to be applied.
// Recomputes only if stateDelta has changed after most recent call to this function
//
// state.GetHash() : stateDelta가 적용될 경우의 새로운 state hash값을 계산.
// 가장 최근에 이 함수를 call한 이후에 stateDelta가 변경되었을 경우에만 재계산.
func (state *State) GetHash() ([]byte, error) {
	logger.Debug("Enter - GetHash()")
	if state.updateStateImpl {
		logger.Debug("updating stateImpl with working-set")
		// PrepareWorkingSet : state에 apply할 stateDelta가 있을 경우에 전달(raw/trie/buckettree에 각각 구현되어 있는 인터페이스)
		state.stateImpl.PrepareWorkingSet(state.stateDelta)
		state.updateStateImpl = false
	}
	hash, err := state.stateImpl.ComputeCryptoHash()
	if err != nil {
		return nil, err
	}
	logger.Debug("Exit - GetHash()")
	return hash, nil
}

// GetTxStateDeltaHash return the hash of the StateDelta
func (state *State) GetTxStateDeltaHash() map[string][]byte {
	return state.txStateDeltaHash
}

// ClearInMemoryChanges remove from memory all the changes to state
//
// state.ClearInMemoryChanges() : 메모리상의 모든 state delta들을 삭제.
func (state *State) ClearInMemoryChanges(changesPersisted bool) {
	state.stateDelta = statemgmt.NewStateDelta()
	state.txStateDeltaHash = make(map[string][]byte)
	state.stateImpl.ClearWorkingSet(changesPersisted)
}

// getStateDelta get changes in state after most recent call to method clearInMemoryChanges
//
// state.GetStateDelta() : 가장 최근의 clearInMemoryChanges() 실행 이후의 state 변화값을 리턴.
func (state *State) getStateDelta() *statemgmt.StateDelta {
	return state.stateDelta
}

// GetSnapshot returns a snapshot of the global state for the current block. stateSnapshot.Release()
// must be called once you are done.
//
// state.GetSnapshot() : 현재 블록의 global state에 대한 스냅샷을 리턴.
// 실행완료 후 스냅샷에 대한 자원 반환을 위해 stateSnapshot.Release()를 꼭 호출해야함!
// type StateSnapshot struct {
//	blockNumber  uint64
//	stateImplItr statemgmt.StateSnapshotIterator (Get(), RawKeyValue(k,v),close() 인터페이스)
//	dbSnapshot   *gorocksdb.Snapshot // RocksDB consistent view 제공.
//	}
func (state *State) GetSnapshot(blockNumber uint64, dbSnapshot *gorocksdb.Snapshot) (*StateSnapshot, error) {
	return newStateSnapshot(blockNumber, dbSnapshot)
}

// FetchStateDeltaFromDB fetches the StateDelta corrsponding to given blockNumber
//
// state.FetchStateDeltaFromDB() : @blockNumber의 stateDelta들을 리턴
func (state *State) FetchStateDeltaFromDB(blockNumber uint64) (*statemgmt.StateDelta, error) {
	stateDeltaBytes, err := db.GetDBHandle().GetFromStateDeltaCF(encodeStateDeltaKey(blockNumber))
	if err != nil {
		return nil, err
	}
	if stateDeltaBytes == nil {
		return nil, nil
	}
	stateDelta := statemgmt.NewStateDelta()
	stateDelta.Unmarshal(stateDeltaBytes)
	return stateDelta, nil
}

// AddChangesForPersistence adds key-value pairs to writeBatch
//
// state.AddChangesForPersistence() : key-value 쌍을 writeBatch에 추가
// ledger.commitTxBatch()에서 호출
func (state *State) AddChangesForPersistence(blockNumber uint64, writeBatch *gorocksdb.WriteBatch) {
	logger.Debug("state.addChangesForPersistence()...start")
	if state.updateStateImpl {
		state.stateImpl.PrepareWorkingSet(state.stateDelta)
		state.updateStateImpl = false
	}
	// state 관리 : 3가지 타입별로 각각 구현
	state.stateImpl.AddChangesForPersistence(writeBatch)

	serializedStateDelta := state.stateDelta.Marshal()
	cf := db.GetDBHandle().StateDeltaCF
	logger.Debugf("Adding state-delta corresponding to block number[%d]", blockNumber)
	// key-value 쌍들을 해당 블록의 컬럼패밀리에 추가, DB에 Write는 ledger.go에서 실행.
	writeBatch.PutCF(cf, encodeStateDeltaKey(blockNumber), serializedStateDelta)
	if blockNumber >= state.historyStateDeltaSize {
		blockNumberToDelete := blockNumber - state.historyStateDeltaSize
		logger.Debugf("Deleting state-delta corresponding to block number[%d]", blockNumberToDelete)
		writeBatch.DeleteCF(cf, encodeStateDeltaKey(blockNumberToDelete))
	} else {
		logger.Debugf("Not deleting previous state-delta. Block number [%d] is smaller than historyStateDeltaSize [%d]",
			blockNumber, state.historyStateDeltaSize)
	}
	logger.Debug("state.addChangesForPersistence()...finished")
}

// ApplyStateDelta applies already prepared stateDelta to the existing state.
// This is an in memory change only. state.CommitStateDelta must be used to
// commit the state to the DB. This method is to be used in state transfer.
//
// state.ApplyStateDelta() : @delta를 현재의 state.stateDelta에 반영.
// 메모리에만 반영되며 DB에 커밋을 위해 state.CommitStateDelta()가 실행되어야 함(바로 아래)
// 이 함수는 state 전송에 사용됨.(for 상태 동기화?)
// tx-batch가 아닌 world state 반영에 사용되는듯
func (state *State) ApplyStateDelta(delta *statemgmt.StateDelta) {
	state.stateDelta = delta
	state.updateStateImpl = true
}

// CommitStateDelta commits the changes from state.ApplyStateDelta to the
// DB.
//
// state.CommitStateDelta() : state.ApplyStateDelta를 DB에 Write/Commit.
func (state *State) CommitStateDelta() error {
	if state.updateStateImpl {
		state.stateImpl.PrepareWorkingSet(state.stateDelta)
		state.updateStateImpl = false
	}

	writeBatch := gorocksdb.NewWriteBatch()
	defer writeBatch.Destroy()
	state.stateImpl.AddChangesForPersistence(writeBatch)
	opt := gorocksdb.NewDefaultWriteOptions()
	defer opt.Destroy()
	return db.GetDBHandle().DB.Write(opt, writeBatch)
}

// DeleteState deletes ALL state keys/values from the DB. This is generally
// only used during state synchronization when creating a new state from
// a snapshot.
//
// state.DeleteState() : state의 모든 key-value를 삭제.
// snapshot으로 부터 new state를 생성할때 state synchronization을 할때만 사용하는게 일반적임
func (state *State) DeleteState() error {
	state.ClearInMemoryChanges(false)
	err := db.GetDBHandle().DeleteState()
	if err != nil {
		logger.Errorf("Error deleting state: %s", err)
	}
	return err
}

func encodeStateDeltaKey(blockNumber uint64) []byte {
	return encodeUint64(blockNumber)
}

func decodeStateDeltaKey(dbkey []byte) uint64 {
	return decodeToUint64(dbkey)
}

func encodeUint64(number uint64) []byte {
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, number)
	return bytes
}

func decodeToUint64(bytes []byte) uint64 {
	return binary.BigEndian.Uint64(bytes)
}
