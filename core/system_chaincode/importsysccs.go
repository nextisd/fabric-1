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
//@@ systemChaincodes 에 있는 개별 SystemChaincode 에 대해, api.RegisterSysCC() 호출
//@@		security 설정되어 있으면 return nil
//@@		!syscc.Enabled || !isWhitelisted(syscc) : 사용할 수 없음 --> return nil
//@@		inproccontroller.Register() 호출
//@@			전역변수 typeRegistry ( map[string]*inprocContainer ) 에 system chaincode 등록
//@@		ChaincodeSpec 생성
//@@		deploySysCC() 호출
//@@			buildSysCC() 호출
//@@				chaincodeDeploymentSpec 생성/리턴
//@@			protos.NewChaincodeDeployTransaction() 호출
//@@				체인코드 delpoy용 트랜잭션 생성
//@@			chaincode.Execute() 호출
//@@				너무 길어서 생략 : core/chaincode/exectransaction.go 참조
//@@				DEPLOY : 내부에서 vm.Deploy() 실행, Register 요청송신/응답처리
//@@				INVOKE / QUERY :내부에서 vm.Start() 실행
//@@					INVOKE : NextState 으로 msg 전송 후 응답처리 (time-out 포함)
//@@					QUERY : chaincode msg 전송 후 응답처리
func RegisterSysCCs() {
	for _, sysCC := range systemChaincodes {
		api.RegisterSysCC(sysCC)
	}
}
