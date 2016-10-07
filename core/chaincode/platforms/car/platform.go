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

package car

import (
	pb "github.com/hyperledger/fabric/protos"
)

// Platform for the CAR type
// CAR라는 타입의 플랫폼을 정의하는 구조체
type Platform struct {
}

// ValidateSpec validates the chaincode specification for CAR types to satisfy
// the platform interface.  This chaincode type currently doesn't
// require anything specific so we just implicitly approve any spec
// 플랫폼 인터페이스 규약에 따라 CAR라는 타입의 체인코드 스펙을 검증.
func (carPlatform *Platform) ValidateSpec(spec *pb.ChaincodeSpec) error {
	return nil
}
