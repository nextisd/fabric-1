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

package api

import (
	"fmt"

	"golang.org/x/net/context"

	"github.com/hyperledger/fabric/core/chaincode"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/core/container/inproccontroller"
	"github.com/hyperledger/fabric/core/peer"
	"github.com/hyperledger/fabric/protos"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
)

var sysccLogger = logging.MustGetLogger("sysccapi")

// SystemChaincode defines the metadata needed to initialize system chaincode
// when the fabric comes up. SystemChaincodes are installed by adding an
// entry in importsysccs.go
//
// SystemChaincode 구조체 : fabric을 로드할때 시스템 체인코드를 초기화 하기 위한 메타데이타 구조체.
// 시스템체인코드들은 importsysccs.go에 상단부에 import문에 추가를 해서, 설치할 수 있다.
type SystemChaincode struct {
	// Enabled a convenient switch to enable/disable system chaincode without
	// having to remove entry from importsysccs.go
	//
	// Enable 변수를 통해 importsysccs.go의 import문을 수정하지 않고도 시스템 체인코드를 enable/disable 설정 가능.
	Enabled bool

	//Unique name of the system chaincode
	//
	Name string

	//Path to the system chaincode; currently not used
	Path string

	//InitArgs initialization arguments to startup the system chaincode
	InitArgs [][]byte

	// Chaincode is the actual chaincode object
	//
	// Chaincode 변수 : Init/Invoke/Query 인터페이스
	Chaincode shim.Chaincode
}

// RegisterSysCC registers the given system chaincode with the peer
//
// RegisterSysCC() : 피어에 시스템 체인코드 등록
func RegisterSysCC(syscc *SystemChaincode) error {
	if peer.SecurityEnabled() {
		sysccLogger.Warning(fmt.Sprintf("Currently system chaincode does support security(%s,%s)", syscc.Name, syscc.Path))
		return nil
	}
	if !syscc.Enabled || !isWhitelisted(syscc) {
		sysccLogger.Info(fmt.Sprintf("system chaincode (%s,%s) disabled", syscc.Name, syscc.Path))
		return nil
	}

	// core/container/inproccontroller/inproccontroller.go
	// Register() : 주어진 경로에 시스템 체인코드를 등록함. 초기화를 위해 deploy를 호출해야함
	err := inproccontroller.Register(syscc.Path, syscc.Chaincode)
	if err != nil {
		errStr := fmt.Sprintf("could not register (%s,%v): %s", syscc.Path, syscc, err)
		sysccLogger.Error(errStr)
		return fmt.Errorf(errStr)
	}

	chaincodeID := &protos.ChaincodeID{Path: syscc.Path, Name: syscc.Name}
	spec := protos.ChaincodeSpec{Type: protos.ChaincodeSpec_Type(protos.ChaincodeSpec_Type_value["GOLANG"]), ChaincodeID: chaincodeID, CtorMsg: &protos.ChaincodeInput{Args: syscc.InitArgs}}

	if deployErr := deploySysCC(context.Background(), &spec); deployErr != nil {
		errStr := fmt.Sprintf("deploy chaincode failed: %s", deployErr)
		sysccLogger.Error(errStr)
		return fmt.Errorf(errStr)
	}

	sysccLogger.Info("system chaincode %s(%s) registered", syscc.Name, syscc.Path)
	return err
}

// buildLocal builds a given chaincode code
//
// buildSysCC() : 체인코드 빌드(deploy를 위한 스펙 세팅)
// ChaincodeDeploymentSpec 구조체
//		ChaincodeSpec *ChaincodeSpec (ChaincodeSpec_Type, ChaincodeID, chaincodeInput, metadata, attributes,...)
//		EffectiveDate *google_protobuf.Timestamp
//		CodePackage   []byte (gzip of the chaincode source. in 프로토콜 스펙 문서, 파일에 해쉬해서 부정 방지)
//		ExecEnv       ChaincodeDeploymentSpec_ExecutionEnvironment (DOCKER or SYSTEM)
func buildSysCC(context context.Context, spec *protos.ChaincodeSpec) (*protos.ChaincodeDeploymentSpec, error) {
	var codePackageBytes []byte
	chaincodeDeploymentSpec := &protos.ChaincodeDeploymentSpec{ExecEnv: protos.ChaincodeDeploymentSpec_SYSTEM, ChaincodeSpec: spec, CodePackage: codePackageBytes}
	return chaincodeDeploymentSpec, nil
}

// deployLocal deploys the supplied chaincode image to the local peer
//
// deploySysCC() : 로컬 피어에 체인코드 이미지를 deploy.
func deploySysCC(ctx context.Context, spec *protos.ChaincodeSpec) error {
	// First build and get the deployment spec
	chaincodeDeploymentSpec, err := buildSysCC(ctx, spec)

	if err != nil {
		sysccLogger.Error(fmt.Sprintf("Error deploying chaincode spec: %v\n\n error: %s", spec, err))
		return err
	}

	// 체인코드 delpoy용 트랜잭션 생성
	transaction, err := protos.NewChaincodeDeployTransaction(chaincodeDeploymentSpec, chaincodeDeploymentSpec.ChaincodeSpec.ChaincodeID.Name)
	if err != nil {
		return fmt.Errorf("Error deploying chaincode: %s ", err)
	}
	// 생성된 트랜잭션 실행
	_, _, err = chaincode.Execute(ctx, chaincode.GetChain(chaincode.DefaultChain), transaction)

	return err
}

func isWhitelisted(syscc *SystemChaincode) bool {
	chaincodes := viper.GetStringMapString("chaincode.system")
	val, ok := chaincodes[syscc.Name]
	enabled := val == "enable" || val == "true" || val == "yes"
	return ok && enabled
}
