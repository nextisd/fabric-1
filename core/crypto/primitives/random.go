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

package primitives

import "crypto/rand"

// GetRandomBytes returns len random looking bytes
// GetRandomBytes()는 입력된 길이만큼의 Tandom 문을 Return한다.
func GetRandomBytes(len int) ([]byte, error) {
	key := make([]byte, len)

	// TODO: rand could fill less bytes then len
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// GetRandomNonce returns a random byte array of length NonceSize
// GetRandomNonce()는 NonceSize(전의된 값=24)길이의 Random Byte 배열을 Return한다.
func GetRandomNonce() ([]byte, error) {
	return GetRandomBytes(NonceSize)
}
