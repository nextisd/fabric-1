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

package statemgmt

import (
	"github.com/tecbot/gorocksdb"
)

// HashableState - Interface that is be implemented by state management
// Different state management implementation can be effiecient for computing crypto-hash for
// state under different workload conditions.
//
// HashableState interface : state 관리를 위한 인터페이스.
// 각기 다른 state management 구현은 서로 다른 부하 조건의 상태에 대한 암호-해쉬를 계산하기 위한 효율적 방법일 수 있다.
type HashableState interface {

	// Initialize this gives a chance to initialize. For instance, state implementation can load some data from DB
	//
	// Initialize() : 초기화.
	Initialize(configs map[string]interface{}) error

	// Get get the value from DB
	//
	// Get() : DB로부터 value를 가져옴.
	Get(chaincodeID string, key string) ([]byte, error)

	// PrepareWorkingSet passes a stateDelta that captures the changes that needs to be applied to the state
	//
	// PrepareWorkingSet() : state에 apply 되어야할 stateDelta를 전달.
	PrepareWorkingSet(stateDelta *StateDelta) error

	// ComputeCryptoHash state implementation to compute crypto-hash of state
	// assuming the stateDelta (passed in PrepareWorkingSet method) is to be applied
	//
	// ComputeCryptoHash() : state의 crypto-hash를 계산.
	// PrepareWorkingSet()에서 전달된 stateDelta가 적용되었다고 가정함.
	ComputeCryptoHash() ([]byte, error)

	// AddChangesForPersistence state implementation to add all the key-value pair that it needs
	// to persist for committing the  stateDelta (passed in PrepareWorkingSet method) to DB.
	// In addition to the information in the StateDelta, the implementation may also want to
	// persist intermediate results for faster crypto-hash computation
	//
	// AddChangesForPersistence() : PrepareWorkingSet에서 전달된 stateDelta를 db에 커밋하는데 필요한 모든 key-value쌍을 추가.
	AddChangesForPersistence(writeBatch *gorocksdb.WriteBatch) error

	// ClearWorkingSet state implementation may clear any data structures that it may have constructed
	// for computing cryptoHash and persisting the changes for the stateDelta (passed in PrepareWorkingSet method)
	//
	// ClearWorkingSet() : 모든 암호-해쉬 계산, stateDelta 저장과 관련된 data structure를 삭제함.
	ClearWorkingSet(changesPersisted bool)

	// GetStateSnapshotIterator state implementation to provide an iterator that is supposed to give
	// All the key-value of global state. A particular implementation may need to remove additional information
	// that the implementation keeps for faster crypto-hash computation. For instance, filter a few of the
	// key-values or remove some data from particular key-values.
	//
	// GetStateSnapshotIterator() : global state의 모든 key-value쌍을 interator형으로 리턴.
	// 좀 더 빠른 암호-해시 계산을 위해 부가적인 정보들에 대한 삭제를 구현할 필요가 있음, 데이터 필터링 등.
	GetStateSnapshotIterator(snapshot *gorocksdb.Snapshot) (StateSnapshotIterator, error)

	// GetRangeScanIterator - state implementation to provide an iterator that is supposed to give
	// All the key-values for a given chaincodeID such that a return key should be lexically greater than or
	// equal to startKey and less than or equal to endKey. If the value for startKey parameter is an empty string
	// startKey is assumed to be the smallest key available in the db for the chaincodeID. Similarly, an empty string
	// for endKey parameter assumes the endKey to be the greatest key available in the db for the chaincodeID
	//
	// GetRangeScanIterator() : @startKey~@endKey 사이(사전순 정렬)의 모든 key-value를 리턴.
	// @param startKey : 빈문자열일 경우는 chaincodeID중 가장 smallest key로 정의
	// @param startKey : 빈문자열일 경우는 chaincodeID중 가장 biggest key로 정의
	GetRangeScanIterator(chaincodeID string, startKey string, endKey string) (RangeScanIterator, error)

	// PerfHintKeyChanged state implementation may be provided with some hints before (e.g., during tx execution)
	// the StateDelta is prepared and passed in PrepareWorkingSet method.
	// A state implementation may use this hint for prefetching relevant data so as if this could improve
	// the performance of ComputeCryptoHash method (when gets called at a later time)
	//
	// PerfHintKeyChanged() : PrepareWorkingSet()에서 stateDelta가 준비되어서 전송되기 전까지 몇가지 hint를 구현해야함(e.g. tx 실행중)
	// ComputeCryptoHash() 함수의 성능 개선등을 위해 관련된 데이터를 pre-fetching 할때 사용. 데이터 캐싱등에 사용 하면 될듯?
	PerfHintKeyChanged(chaincodeID string, key string)
}

// StateSnapshotIterator An interface that is to be implemented by the return value of
// GetStateSnapshotIterator method in the implementation of HashableState interface
//
// StateSnapshotIterator interface : HashableState.GetStateSnapshotIterator()의 리턴값 인터페이스.
type StateSnapshotIterator interface {

	// Next moves to next key-value. Returns true if next key-value exists
	//
	// Next() : 다음 key-value로 이동, 다음 key-value 존재시 true 리턴.
	Next() bool

	// GetRawKeyValue returns next key-value
	//
	// GetRawKeyValue() : 다음 key-value 리턴??
	// KTODO, /ledger/statemgmt/state/state_snapshot.go에는 현재 iterator의 위치에 해당하는 k/v를 리턴하라고 되어있는데..
	//        실제로 3가지 statemgmt 구현을 찾아봐도 현재 위치꺼 가져오는 것으로 보임.
	GetRawKeyValue() ([]byte, []byte)

	// Close releases resources occupied by the iterator
	//
	// interator에 할당된 자원 반환.
	Close()
}

// RangeScanIterator - is to be implemented by the return value of
// GetRangeScanIterator method in the implementation of HashableState interface
//
// RangeScanIterator interface : HashableState.GetRangeScanIterator()의 리턴값 인터페이스
type RangeScanIterator interface {

	// Next moves to next key-value. Returns true if next key-value exists
	//
	// Next() : 다음 key-value로 이동. 다음 key-value 존재시 true 리턴.
	Next() bool

	// GetKeyValue returns next key-value
	//
	// GetKeyValue() : 다음 key-value 리턴.
	GetKeyValue() (string, []byte)

	// Close releases resources occupied by the iterator
	//
	// interator에 할당된 자원 반환
	Close()
}
