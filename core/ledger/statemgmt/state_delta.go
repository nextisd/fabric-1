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
	"bytes"
	"fmt"
	"sort"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/core/util"
)

// StateDelta holds the changes to existing state. This struct is used for holding the uncommitted changes during execution of a tx-batch
// Also, to be used for transferring the state to another peer in chunks
//
// StateDelta 구조체 : state 변화를 저장. tx-batch 실행중 발생된 un-committed change를 저장하는데 사용함.
// 다른 피어들에게 state를 전송할때도 사용함.
type StateDelta struct {
	// ChaincodeStateDelta : {chaincodeID, UpdatedKVs}
	ChaincodeStateDeltas map[string]*ChaincodeStateDelta
	// RollBackwards allows one to contol whether this delta will roll the state
	// forwards or backwards.
	//
	// RollBackward는 이 delta로 state를 roll forwards/backwards 여부를 제어하는데 사용.
	RollBackwards bool
}

// NewStateDelta constructs an empty StateDelta struct
//
// NewStateDelta() : empty StateDelta 구조체 생성.
func NewStateDelta() *StateDelta {
	return &StateDelta{make(map[string]*ChaincodeStateDelta), false}
}

// Get get the state from delta if exists
//
// Get() : stateDelta로 부터 @chaincodeID의 state를 가져옴.
func (stateDelta *StateDelta) Get(chaincodeID string, key string) *UpdatedValue {
	// TODO Cache?
	chaincodeStateDelta, ok := stateDelta.ChaincodeStateDeltas[chaincodeID]
	if ok {
		// UpdatedValue : key에 해당하는 Value와 PreviousValue를 가져오는듯?
		return chaincodeStateDelta.get(key)
	}
	return nil
}

// Set sets state value for a key
//
// Set() : @key에 대한 state value를 세팅
func (stateDelta *StateDelta) Set(chaincodeID string, key string, value, previousValue []byte) {
	// getOrCreateChaincodeStateDelta() : @chaincodeID의 stateDelta를 리턴하거나, 신규 생성.
	chaincodeStateDelta := stateDelta.getOrCreateChaincodeStateDelta(chaincodeID)
	chaincodeStateDelta.set(key, value, previousValue)
	return
}

// Delete deletes a key from the state
//
// Delete() : state에서 key 삭제.
func (stateDelta *StateDelta) Delete(chaincodeID string, key string, previousValue []byte) {
	chaincodeStateDelta := stateDelta.getOrCreateChaincodeStateDelta(chaincodeID)
	chaincodeStateDelta.remove(key, previousValue)
	return
}

// IsUpdatedValueSet returns true if a update value is already set for
// the given chaincode ID and key.
//
// IsUpdatedValueSet() : Previous Value가 state delta에 세팅되어 있는지 체크.
// state.Set()에서 호출 : Previous Value가	있으면 그대로 두고,
// 									  	없으면 state.Get()해서 세팅하고나서
//						Value를 다시 state.Set() 세팅처리.
func (stateDelta *StateDelta) IsUpdatedValueSet(chaincodeID, key string) bool {
	chaincodeStateDelta, ok := stateDelta.ChaincodeStateDeltas[chaincodeID]
	if !ok {
		return false
	}
	if _, ok := chaincodeStateDelta.UpdatedKVs[key]; ok {
		return true
	}
	return false
}

// ApplyChanges merges another delta - if a key is present in both, the value of the existing key is overwritten
//
// ApplyChanges() : 다른 delta들을 merge. key가 중복될 경우 value는 overwrite됨.
func (stateDelta *StateDelta) ApplyChanges(anotherStateDelta *StateDelta) {
	for chaincodeID, chaincodeStateDelta := range anotherStateDelta.ChaincodeStateDeltas {
		existingChaincodeStateDelta, existingChaincode := stateDelta.ChaincodeStateDeltas[chaincodeID]
		for key, valueHolder := range chaincodeStateDelta.UpdatedKVs {
			var previousValue []byte
			if existingChaincode {
				existingUpdateValue, existingUpdate := existingChaincodeStateDelta.UpdatedKVs[key]
				if existingUpdate {
					// The existing state delta already has an updated value for this key.
					//
					// 위의 UpdatedKVs[key]에 해당하는 state delta가 존재시 updated value 역시 존재함.
					previousValue = existingUpdateValue.PreviousValue
				} else {
					// Use the previous value set in the new state delta
					//
					// 새로운 state delta의 previous value를 사용
					previousValue = valueHolder.PreviousValue
				}
			} else {
				// Use the previous value set in the new state delta
				//
				//  새로운 state delta의 previous value를 사용
				previousValue = valueHolder.PreviousValue
			}

			if valueHolder.IsDeleted() {
				stateDelta.Delete(chaincodeID, key, previousValue)
			} else {
				stateDelta.Set(chaincodeID, key, valueHolder.Value, previousValue)
			}
		}
	}
}

// IsEmpty checks whether StateDelta contains any data
//
// IsEmpty() : stateDelta가 비었는지 체크
func (stateDelta *StateDelta) IsEmpty() bool {
	return len(stateDelta.ChaincodeStateDeltas) == 0
}

// GetUpdatedChaincodeIds return the chaincodeIDs that are prepsent in the delta
// If sorted is true, the method return chaincodeIDs in lexicographical sorted order
//
// GetUpdatedChaincodeIds() : delta에 존재하는 chaincodeID들을 리턴
// @param sorted : true일때는 chaincodeID들을 사전순으로 정렬
func (stateDelta *StateDelta) GetUpdatedChaincodeIds(sorted bool) []string {
	updatedChaincodeIds := make([]string, len(stateDelta.ChaincodeStateDeltas))
	i := 0
	for k := range stateDelta.ChaincodeStateDeltas {
		updatedChaincodeIds[i] = k
		i++
	}
	if sorted {
		sort.Strings(updatedChaincodeIds)
	}
	return updatedChaincodeIds
}

// GetUpdates returns changes associated with given chaincodeId
//
// GetUpdates() : @chaincodeID에 관련된 변경사항을 리턴(UpdatedKVs: map{key,{value,prev_value}})
func (stateDelta *StateDelta) GetUpdates(chaincodeID string) map[string]*UpdatedValue {
	chaincodeStateDelta := stateDelta.ChaincodeStateDeltas[chaincodeID]
	if chaincodeStateDelta == nil {
		return nil
	}
	return chaincodeStateDelta.UpdatedKVs
}

// getOrCreateChaincodeStateDelta() : @chaincodeID의 stateDelta를 리턴하거나, 신규 생성.
func (stateDelta *StateDelta) getOrCreateChaincodeStateDelta(chaincodeID string) *ChaincodeStateDelta {
	chaincodeStateDelta, ok := stateDelta.ChaincodeStateDeltas[chaincodeID]
	if !ok {
		chaincodeStateDelta = newChaincodeStateDelta(chaincodeID)
		stateDelta.ChaincodeStateDeltas[chaincodeID] = chaincodeStateDelta
	}
	return chaincodeStateDelta
}

// ComputeCryptoHash computes crypto-hash for the data held
// returns nil if no data is present
//
// ComputeCryptoHash() :stateDelta를 암호-해시 계산후 해쉬값(sha3.ShakeSum256처리)을 리턴.
func (stateDelta *StateDelta) ComputeCryptoHash() []byte {
	if stateDelta.IsEmpty() {
		return nil
	}
	var buffer bytes.Buffer
	sortedChaincodeIds := stateDelta.GetUpdatedChaincodeIds(true)
	for _, chaincodeID := range sortedChaincodeIds {
		buffer.WriteString(chaincodeID)
		chaincodeStateDelta := stateDelta.ChaincodeStateDeltas[chaincodeID]
		sortedKeys := chaincodeStateDelta.getSortedKeys()
		for _, key := range sortedKeys {
			buffer.WriteString(key)
			updatedValue := chaincodeStateDelta.get(key)
			if !updatedValue.IsDeleted() {
				buffer.Write(updatedValue.Value)
			}
		}
	}
	hashingContent := buffer.Bytes()
	logger.Debugf("computing hash on %#v", hashingContent)
	return util.ComputeCryptoHash(hashingContent)
}

//ChaincodeStateDelta maintains state for a chaincode
//
// ChaincodeStateDelta 구조체 : ChaincodeID, UpdatedKVs(map{key,{value,prev_value}})
type ChaincodeStateDelta struct {
	ChaincodeID string
	UpdatedKVs  map[string]*UpdatedValue
}

// newChaincodeStateDelta() : ChaincodeStateDelta 신규 생성
func newChaincodeStateDelta(chaincodeID string) *ChaincodeStateDelta {
	return &ChaincodeStateDelta{chaincodeID, make(map[string]*UpdatedValue)}
}

// get() : @key에 해당하는 UpdateKVs 가져오기
func (chaincodeStateDelta *ChaincodeStateDelta) get(key string) *UpdatedValue {
	// TODO Cache?
	return chaincodeStateDelta.UpdatedKVs[key]
}

// set() : chaincodeStateDelta를 @updatedValue로 업데이트 처리.
func (chaincodeStateDelta *ChaincodeStateDelta) set(key string, updatedValue, previousValue []byte) {
	updatedKV, ok := chaincodeStateDelta.UpdatedKVs[key]
	if ok {
		// Key already exists, just set the updated value
		//
		// key가 이미 존재시에는 updateValue로 Value를 업데이트.
		updatedKV.Value = updatedValue
	} else {
		// New key. Create a new entry in the map
		//
		// 새로운 key인 경우는 map에 신규 k/v를 추가함.
		chaincodeStateDelta.UpdatedKVs[key] = &UpdatedValue{updatedValue, previousValue}
	}
}

// remove() : @key에 해당하는 value 삭제
func (chaincodeStateDelta *ChaincodeStateDelta) remove(key string, previousValue []byte) {
	updatedKV, ok := chaincodeStateDelta.UpdatedKVs[key]
	if ok {
		// Key already exists, just set the value
		//
		// Key가 존재시, Value를 nil로 세팅
		updatedKV.Value = nil
	} else {
		// New key. Create a new entry in the map
		//
		// 새로운 key일 경우, map에 entry 추가하고 value는 nil로 세팅
		chaincodeStateDelta.UpdatedKVs[key] = &UpdatedValue{nil, previousValue}
	}
}

// hasChanges() : ChaincodeStateDelta에 변경사항이 있는지 체크
func (chaincodeStateDelta *ChaincodeStateDelta) hasChanges() bool {
	return len(chaincodeStateDelta.UpdatedKVs) > 0
}

// getSortedKeys() : ChaincodeStateDelta의 key를 정렬후 리턴
func (chaincodeStateDelta *ChaincodeStateDelta) getSortedKeys() []string {
	updatedKeys := []string{}
	for k := range chaincodeStateDelta.UpdatedKVs {
		updatedKeys = append(updatedKeys, k)
	}
	sort.Strings(updatedKeys)
	logger.Debugf("Sorted keys = %#v", updatedKeys)
	return updatedKeys
}

// UpdatedValue holds the value for a key
//
// UpdatedValue 구조체 : key에 해당하는 value를 저장, 상태 변화시 Value에 업데이트 함.
type UpdatedValue struct {
	Value         []byte
	PreviousValue []byte
}

// IsDeleted checks whether the key was deleted
//
// IsDeleted() : key가 삭제되었는지 체크
func (updatedValue *UpdatedValue) IsDeleted() bool {
	return updatedValue.Value == nil
}

// GetValue returns the value
//
// GetValue() : UpdatedValue.Value 리턴
func (updatedValue *UpdatedValue) GetValue() []byte {
	return updatedValue.Value
}

// GetPreviousValue returns the previous value
//
// GetPreviousValue() : updatedValue.PreviousValue 리턴
func (updatedValue *UpdatedValue) GetPreviousValue() []byte {
	return updatedValue.PreviousValue
}

// marshalling / Unmarshalling code
// We need to revisit the following when we define proto messages
// for state related structures for transporting. May be we can
// completely get rid of custom marshalling / Unmarshalling of a state delta
//
// marshalling / Unmarshalling code
// state 관련한 구조체의 전송에 대한 proto message를 정의할때 아래 코드들을 다시 정리해야함
// 아래에 구현한 state delta에 대한 custom marshalling / Unmarshalling 코드들을 제거 할수 있을것임.

// Marshal serializes the StateDelta
// Marshal() : StateDelta를 serialize(byte화)
func (stateDelta *StateDelta) Marshal() (b []byte) {
	buffer := proto.NewBuffer([]byte{})
	err := buffer.EncodeVarint(uint64(len(stateDelta.ChaincodeStateDeltas)))
	if err != nil {
		// in protobuf code the error return is always nil
		panic(fmt.Errorf("This error should not occure: %s", err))
	}
	for chaincodeID, chaincodeStateDelta := range stateDelta.ChaincodeStateDeltas {
		buffer.EncodeStringBytes(chaincodeID)
		chaincodeStateDelta.marshal(buffer)
	}
	b = buffer.Bytes()
	return
}

// marshal() : ChaincodeStateDelta를 serialize
func (chaincodeStateDelta *ChaincodeStateDelta) marshal(buffer *proto.Buffer) {
	err := buffer.EncodeVarint(uint64(len(chaincodeStateDelta.UpdatedKVs)))
	if err != nil {
		panic(fmt.Errorf("This error should not occur: %s", err))
	}
	for key, valueHolder := range chaincodeStateDelta.UpdatedKVs {
		err = buffer.EncodeStringBytes(key)
		if err != nil {
			panic(fmt.Errorf("This error should not occur: %s", err))
		}
		chaincodeStateDelta.marshalValueWithMarker(buffer, valueHolder.Value)
		chaincodeStateDelta.marshalValueWithMarker(buffer, valueHolder.PreviousValue)
	}
	return
}

// marshalValueWithMarker() : 마커(protobuf 타입?)를 추가해서 mashalling
func (chaincodeStateDelta *ChaincodeStateDelta) marshalValueWithMarker(buffer *proto.Buffer, value []byte) {
	if value == nil {
		// Just add a marker that the value is nil
		//
		// value가 nil인 marker를 추가
		err := buffer.EncodeVarint(uint64(0))
		if err != nil {
			panic(fmt.Errorf("This error should not occur: %s", err))
		}
		return
	}
	err := buffer.EncodeVarint(uint64(1))
	if err != nil {
		panic(fmt.Errorf("This error should not occur: %s", err))
	}
	// If the value happen to be an empty byte array, it would appear as a nil during
	// deserialization - see method 'unmarshalValueWithMarker'
	//
	// value가 비어있는 byte array일 경우, unmarshalValueWithMarker()에서 deserialization할경우 nil로 변환될것임.
	err = buffer.EncodeRawBytes(value)
	if err != nil {
		panic(fmt.Errorf("This error should not occur: %s", err))
	}
}

// Unmarshal deserializes StateDelta
//
// Unmarshal() : StateDelta를 deserialize
func (stateDelta *StateDelta) Unmarshal(bytes []byte) error {
	buffer := proto.NewBuffer(bytes)
	size, err := buffer.DecodeVarint()
	if err != nil {
		return fmt.Errorf("Error unmarashaling size: %s", err)
	}
	stateDelta.ChaincodeStateDeltas = make(map[string]*ChaincodeStateDelta, size)
	for i := uint64(0); i < size; i++ {
		chaincodeID, err := buffer.DecodeStringBytes()
		if err != nil {
			return fmt.Errorf("Error unmarshaling chaincodeID : %s", err)
		}
		chaincodeStateDelta := newChaincodeStateDelta(chaincodeID)
		err = chaincodeStateDelta.unmarshal(buffer)
		if err != nil {
			return fmt.Errorf("Error unmarshalling chaincodeStateDelta : %s", err)
		}
		stateDelta.ChaincodeStateDeltas[chaincodeID] = chaincodeStateDelta
	}

	return nil
}

// unmarshal() : ChaincodeStateDelta를 deserialize
func (chaincodeStateDelta *ChaincodeStateDelta) unmarshal(buffer *proto.Buffer) error {
	size, err := buffer.DecodeVarint()
	if err != nil {
		return fmt.Errorf("Error unmarshaling state delta: %s", err)
	}
	chaincodeStateDelta.UpdatedKVs = make(map[string]*UpdatedValue, size)
	for i := uint64(0); i < size; i++ {
		key, err := buffer.DecodeStringBytes()
		if err != nil {
			return fmt.Errorf("Error unmarshaling state delta : %s", err)
		}
		value, err := chaincodeStateDelta.unmarshalValueWithMarker(buffer)
		if err != nil {
			return fmt.Errorf("Error unmarshaling state delta : %s", err)
		}
		previousValue, err := chaincodeStateDelta.unmarshalValueWithMarker(buffer)
		if err != nil {
			return fmt.Errorf("Error unmarshaling state delta : %s", err)
		}
		chaincodeStateDelta.UpdatedKVs[key] = &UpdatedValue{value, previousValue}
	}
	return nil
}

// unmarshalValueWithMarker() : 마커(protobuf 타입?)를 추가해서 unmashalling
func (chaincodeStateDelta *ChaincodeStateDelta) unmarshalValueWithMarker(buffer *proto.Buffer) ([]byte, error) {
	valueMarker, err := buffer.DecodeVarint()
	if err != nil {
		return nil, fmt.Errorf("Error unmarshaling state delta : %s", err)
	}
	if valueMarker == 0 {
		return nil, nil
	}
	value, err := buffer.DecodeRawBytes(false)
	if err != nil {
		return nil, fmt.Errorf("Error unmarhsaling state delta : %s", err)
	}
	// protobuff makes an empty []byte into a nil. So, assigning an empty byte array explicitly
	//
	// protobuf는 비어있는 byte array를 nil로 변환함. 따라서 비어있는 byte array를 명시적으로 할당해야함.
	if value == nil {
		value = []byte{}
	}
	return value, nil
}
