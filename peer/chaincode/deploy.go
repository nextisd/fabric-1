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

package chaincode

import (
	"fmt"

	"golang.org/x/net/context"

	"github.com/hyperledger/fabric/peer/common"
	"github.com/spf13/cobra"
)

// Cmd returns the cobra command for Chaincode Deploy
func deployCmd() *cobra.Command {
	return chaincodeDeployCmd
}

var chaincodeDeployCmd = &cobra.Command{
	Use:       "deploy",
	Short:     fmt.Sprintf("Deploy the specified chaincode to the network."),
	Long:      fmt.Sprintf(`Deploy the specified chaincode to the network.`),
	ValidArgs: []string{"1"},
	RunE: func(cmd *cobra.Command, args []string) error {
		return chaincodeDeploy(cmd, args)
	},
}

// chaincodeDeploy deploys the chaincode. On success, the chaincode name
// (hash) is printed to STDOUT for use by subsequent chaincode-related CLI
// commands.
//@@ chaincodeDeploy() 는 chaincode 를 deploy
//@@ 성공시 chaincode name (hash 값) 을 표준출력으로 print
//@@ chaincode name : CLI 를 통해 해당 chaincode invoke/query 시 필수 인자로 사용됨
func chaincodeDeploy(cmd *cobra.Command, args []string) error {
	//@@ ChaincodeSpec (protobuf) 를 생성하고 field 값 세팅
	spec, err := getChaincodeSpecification(cmd)
	if err != nil {
		return err
	}

	//@@ GetDevopsClient local peer 와 새로운 gRPC connection 을 맺고,
	//@@ DevopsClient object 를 생성하여 리턴
	devopsClient, err := common.GetDevopsClient(cmd)
	if err != nil {
		return fmt.Errorf("Error building %s: %s", chainFuncName, err)
	}

	//@@ "/protos.Devops/Deploy" 로 gRPC 요청전송/응답수신, 응답 리턴
	chaincodeDeploymentSpec, err := devopsClient.Deploy(context.Background(), spec)
	if err != nil {
		return fmt.Errorf("Error building %s: %s\n", chainFuncName, err)
	}
	logger.Infof("Deploy result: %s", chaincodeDeploymentSpec.ChaincodeSpec)
	fmt.Printf("Deploy chaincode: %s\n", chaincodeDeploymentSpec.ChaincodeSpec.ChaincodeID.Name)

	return nil
}
