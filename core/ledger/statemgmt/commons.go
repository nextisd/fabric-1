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

	"github.com/op/go-logging"
)

var logger = logging.MustGetLogger("statemgmt")

var stateKeyDelimiter = []byte{0x00}

// ConstructCompositeKey returns a []byte that uniquely represents a given chaincodeID and key.
// This assumes that chaincodeID does not contain a 0x00 byte, but the key may
// TODO:enforce this restriction on chaincodeID or use length prefixing here instead of delimiter
//
// ConstructCompositeKey() : @chaincodeID와 @key를 unique 하게 표현된 byte array로 리턴.
// @chaincodeID는 0x00를 포함해서는 안되나, key에는 포함 가능.
// TODO:chaincodeID에 대한 이러한 제약사항을 강제하거나, delimiter 대신 length prefixing을 사용하도록 구현.
func ConstructCompositeKey(chaincodeID string, key string) []byte {
	return bytes.Join([][]byte{[]byte(chaincodeID), []byte(key)}, stateKeyDelimiter)
}

// DecodeCompositeKey decodes the compositeKey constructed by ConstructCompositeKey method
// back to the original chaincodeID and key form
//
// DecodeCompositeKey() : ConstructCompositeKey()로 만들어진 compositeKey를 원래의 chaincodeID와 key로 리턴.
func DecodeCompositeKey(compositeKey []byte) (string, string) {
	split := bytes.SplitN(compositeKey, stateKeyDelimiter, 2)
	return string(split[0]), string(split[1])
}

// Copy returns a copy of given bytes
//
// Copy() : @src []byte의 복사본 리턴
func Copy(src []byte) []byte {
	dest := make([]byte, len(src))
	copy(dest, src)
	return dest
}
