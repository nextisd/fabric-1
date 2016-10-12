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

package system_chaincode

import (
	"github.com/hyperledger/fabric/core/system_chaincode/api"
	//import system chain codes here
	//
	// 여기에 시스템 체인코드를 추가할것!
	"github.com/hyperledger/fabric/bddtests/syschaincode/noop"
)

//see systemchaincode_test.go for an example using "sample_syscc"
//
// "sample_syscc"를 사용하는 예제는 systemchaincode_test.go에서 확인할것
var systemChaincodes = []*api.SystemChaincode{
	{
		Enabled:   true,
		Name:      "noop",
		Path:      "github.com/hyperledger/fabric/bddtests/syschaincode/noop",
		InitArgs:  [][]byte{},
		Chaincode: &noop.SystemChaincode{},
	}}

//RegisterSysCCs is the hook for system chaincodes where system chaincodes are registered with the fabric
//note the chaincode must still be deployed and launched like a user chaincode will be
//
// RegisterSysCCs() : fabric에 등록된 시스템체인코드들을 등록처리
// 현재까지는, 시스템체인코드도 유저 체인코드처럼 deploy되고 launch(execute)되어야 함.
func RegisterSysCCs() {
	for _, sysCC := range systemChaincodes {
		api.RegisterSysCC(sysCC)
	}
}
