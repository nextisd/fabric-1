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

// StateDeltaIterator - An iterator implementation over state-delta
//
// StateDeltaIterator 구조체 : state delta의 interator 구현
type StateDeltaIterator struct {
	updates         map[string]*UpdatedValue
	relevantKeys    []string
	currentKeyIndex int
	done            bool
}

// NewStateDeltaRangeScanIterator - return an iterator for performing a range scan over a state-delta object
//
// NewStateDeltaRangeScanIterator() : state-delta 객체 range scan(@startKey~@endKey)을 처리하는 iterator를 리턴
func NewStateDeltaRangeScanIterator(delta *StateDelta, chaincodeID string, startKey string, endKey string) *StateDeltaIterator {
	// updates에 @chaincodeID에 해당하는 UpdatedKVs를 가져옴
	updates := delta.GetUpdates(chaincodeID)
	return &StateDeltaIterator{updates, retrieveRelevantKeys(updates, startKey, endKey), -1, false}
}

// retrieveRelevantKeys() : @startKey~@endKey중 value가 존재하는 key들의 string array를 리턴
func retrieveRelevantKeys(updates map[string]*UpdatedValue, startKey string, endKey string) []string {
	relevantKeys := []string{}
	if updates == nil {
		return relevantKeys
	}
	for k, v := range updates {
		if k >= startKey && (endKey == "" || k <= endKey) && !v.IsDeleted() {
			relevantKeys = append(relevantKeys, k)
		}
	}
	return relevantKeys
}

// Next - see interface 'RangeScanIterator' for details
//
// itr.Next() : 다음 key-value로 이동. 다음 key-value 존재시 true 리턴.
func (itr *StateDeltaIterator) Next() bool {
	itr.currentKeyIndex++
	if itr.currentKeyIndex < len(itr.relevantKeys) {
		return true
	}
	itr.currentKeyIndex--
	itr.done = true
	return false
}

// GetKeyValue - see interface 'RangeScanIterator' for details
//
// itr.GetkeyValue() : 다음 key-value 리턴.
func (itr *StateDeltaIterator) GetKeyValue() (string, []byte) {
	if itr.done {
		logger.Warning("Iterator used after it has been exhausted. Last retrieved value will be returned")
	}
	key := itr.relevantKeys[itr.currentKeyIndex]
	value := itr.updates[key].GetValue()
	return key, value
}

// Close - see interface 'RangeScanIterator' for details
//
// itr.Close() : interator에 할당된 자원 반환
func (itr *StateDeltaIterator) Close() {
}

// ContainsKey - checks wether the given key is present in the state-delta
//
// itr.ContainsKey() : @key가 state-delta에 존재하는지 체크
func (itr *StateDeltaIterator) ContainsKey(key string) bool {
	_, ok := itr.updates[key]
	return ok
}
