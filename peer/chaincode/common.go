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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/hyperledger/fabric/core"
	"github.com/hyperledger/fabric/peer/common"
	"github.com/hyperledger/fabric/peer/util"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/net/context"
)

//@@ ChaincodeSpec (protobuf) 를 생성하고 field 값 세팅
func getChaincodeSpecification(cmd *cobra.Command) (*pb.ChaincodeSpec, error) {
	spec := &pb.ChaincodeSpec{}
	//@@ command line 에서 들어온 실행인자들을 check
	if err := checkChaincodeCmdParams(cmd); err != nil {
		return spec, err
	}

	// Build the spec
	//@@ ChaincodeInput (protobuf) 에 chaincodeCtorJSON (string) 를 unmarshal
	input := &pb.ChaincodeInput{}
	if err := json.Unmarshal([]byte(chaincodeCtorJSON), &input); err != nil {
		return spec, fmt.Errorf("Chaincode argument error: %s", err)
	}

	//@@ attributes (string) 에 chaincodeAttributesJSON (string) 를 unmarshal
	var attributes []string
	if err := json.Unmarshal([]byte(chaincodeAttributesJSON), &attributes); err != nil {
		return spec, fmt.Errorf("Chaincode argument error: %s", err)
	}

	//@@ chaincodeLang (string) 의 문자들을 모두 대문자로 변경
	chaincodeLang = strings.ToUpper(chaincodeLang)
	//@@ ChaincodeSpec (protobuf) 에 입력된 인자들을 세팅
	spec = &pb.ChaincodeSpec{
		Type:        pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value[chaincodeLang]),
		ChaincodeID: &pb.ChaincodeID{Path: chaincodePath, Name: chaincodeName},
		CtorMsg:     input,
		Attributes:  attributes,
	}
	// If security is enabled, add client login token
	if core.SecurityEnabled() {
		//@@ chaincodeUsr (string) 이 "" 이면 에러 (입력 인자 없음)  
		if chaincodeUsr == common.UndefinedParamValue {
			return spec, errors.New("Must supply username for chaincode when security is enabled")
		}

		// Retrieve the CLI data storage path
		// Returns /var/openchain/production/client/
		//@@ client login token 을 보관하는 local path 를 받음
		//@@ path : "peer.fileSystemPath" (core.yaml) + "/client/"
		localStore := util.GetCliFilePath()

		// Check if the user is logged in before sending transaction
		//@@ 파일이 있는지 check --> 없으면 에러 (아직 로그인 안 했음)
		//@@ "peer.fileSystemPath" (core.yaml) + "/client/" + "loginToken_" + "username"
		if _, err := os.Stat(localStore + "loginToken_" + chaincodeUsr); err == nil {
			logger.Infof("Local user '%s' is already logged in. Retrieving login token.\n", chaincodeUsr)

			// Read in the login token
			//@@ login token 파일에서 token 읽기
			token, err := ioutil.ReadFile(localStore + "loginToken_" + chaincodeUsr)
			if err != nil {
				panic(fmt.Errorf("Fatal error when reading client login token: %s\n", err))
			}

			// Add the login token to the chaincodeSpec
			//@@ ChaincodeSpec 에 읽은 token 세팅 -
			spec.SecureContext = string(token)

			// If privacy is enabled, mark chaincode as confidential
			//@@ "security.privacy" (core.yaml) 이 true 면,
			//@@ ChaincodeSpec 의 ConfidentialityLevel = ConfidentialityLevel_CONFIDENTIAL
			if viper.GetBool("security.privacy") {
				logger.Info("Set confidentiality level to CONFIDENTIAL.\n")
				spec.ConfidentialityLevel = pb.ConfidentialityLevel_CONFIDENTIAL
			}
		} else {
			//@@ login token 파일이 없으면 에러 (아직 로그인 안 했음)
			// Check if the token is not there and fail
			if os.IsNotExist(err) {
				return spec, fmt.Errorf("User '%s' not logged in. Use the 'peer network login' command to obtain a security token.", chaincodeUsr)
			}
			// Unexpected error
			panic(fmt.Errorf("Fatal error when checking for client login token: %s\n", err))
		}
	} else {
		//@@ chaincodeUsr (string) 이 "" 이면 warning
		if chaincodeUsr != common.UndefinedParamValue {
			logger.Warning("Username supplied but security is disabled.")
		}
		//@@ "security.privacy" (core.yaml) 이 true 면, 에러처리
		//@@ 상위인 core.SecurityEnabled() 가 true 아님
		if viper.GetBool("security.privacy") {
			panic(errors.New("Privacy cannot be enabled as requested because security is disabled"))
		}
	}
	return spec, nil
}

// chaincodeInvokeOrQuery invokes or queries the chaincode. If successful, the
// INVOKE form prints the transaction ID on STDOUT, and the QUERY form prints
// the query result on STDOUT. A command-line flag (-r, --raw) determines
// whether the query result is output as raw bytes, or as a printable string.
// The printable form is optionally (-x, --hex) a hexadecimal representation
// of the query response. If the query response is NIL, nothing is output.
//@@ chaincodeInvokeOrQuery() 는 chaincode 를 invoke / query
//@@ invoke 성공 : 표준출력에 Tx ID 를 출력
//@@ query  성공 : 표준출력에 조회 결과를 출력 (조회결과 없으면 출력없음)
//@@                   command-line flag 로 출력 방식 결정 (-r, --raw) : (raw byte) / (printable string)
//@@ (printable string) 은 선택적으로 (-x, --hex) - 16진수 표현 있음
func chaincodeInvokeOrQuery(cmd *cobra.Command, args []string, invoke bool) (err error) {
	//@@ ChaincodeSpec (protobuf) 를 생성하고 field 값 세팅
	spec, err := getChaincodeSpecification(cmd)
	if err != nil {
		return err
	}

	//@@ GetDevopsClient peer 의 새로운 client connection 을 리턴
	//@@ see "github.com/hyperledger/fabric/protos" NewDevopsClient()
	devopsClient, err := common.GetDevopsClient(cmd)
	if err != nil {
		return fmt.Errorf("Error building %s: %s", chainFuncName, err)
	}

	// Build the ChaincodeInvocationSpec message
	//@@ ChaincodeInvocationSpec (protobuf) 생성
	invocation := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}
	if customIDGenAlg != common.UndefinedParamValue {
		invocation.IdGenerationAlg = customIDGenAlg
	}

	var resp *pb.Response
	if invoke {
		//@@ "/protos.Devops/Invoke" 로 gRPC 요청 보냄
		resp, err = devopsClient.Invoke(context.Background(), invocation)
	} else {
		//@@ "/protos.Devops/Query" 로 gRPC 요청 보냄
		resp, err = devopsClient.Query(context.Background(), invocation)
	}

	if err != nil {
		if invoke {
			err = fmt.Errorf("Error invoking %s: %s\n", chainFuncName, err)
		} else {
			err = fmt.Errorf("Error querying %s: %s\n", chainFuncName, err)
		}
		return
	}

	//@ invoke 면, 성공시 Tx ID 를 리턴함 
	if invoke {
		transactionID := string(resp.Msg)
		logger.Infof("Successfully invoked transaction: %s(%s)", invocation, transactionID)
	} else {
		logger.Infof("Successfully queried transaction: %s", invocation)
		
		//@ 해당 데이터가 없으면 output == nil 
		if resp != nil {
			//@ output 형식이 Raw 인 경우 
			if chaincodeQueryRaw {
				//@ output 형식이 Hexa 인 경우 --> Raw 에는 Hexa 미지원, 에러 
				if chaincodeQueryHex {
					err = errors.New("Options --raw (-r) and --hex (-x) are not compatible\n")
					return
				}
				fmt.Print("Query Result (Raw): ")
				os.Stdout.Write(resp.Msg)

			//@ output 형식이 Raw 가 아닌 경우 
			} else {
				//@ output 형식이 Hexa 인 경우 --> Hexa Code 로 출력 
				if chaincodeQueryHex {
					fmt.Printf("Query Result: %x\n", resp.Msg)
				} else {
				//@ output 형식이 Hexa 가 아닌 경우 --> String 으로 출력 
					fmt.Printf("Query Result: %s\n", string(resp.Msg))
				}
			}
		}
	}
	return nil
}

//@@ chaincode command 에 들어오는 flag 를 검사
//@@ ( -a, --attributes ) 와 ( -c, --ctor ) flag 만 검사
func checkChaincodeCmdParams(cmd *cobra.Command) error {

	//@@ chaincodeName (chaincode name ) : --name, -n 플래그로 들어온 string 보관
	//@@ chaincodePath (chaincode path ) : --path, -p 플래그로 들어온 string 보관 
	//@@ chaincode name 또는 path 가 "" 이면 에러처리 (즉, 필수)
	if chaincodeName == common.UndefinedParamValue {
		if chaincodePath == common.UndefinedParamValue {
			return fmt.Errorf("Must supply value for %s path parameter.\n", chainFuncName)
		}
	}

	// Check that non-empty chaincode parameters contain only Args as a key.
	// Type checking is done later when the JSON is actually unmarshaled
	// into a pb.ChaincodeInput. To better understand what's going
	// on here with JSON parsing see http://blog.golang.org/json-and-go -
	// Generic JSON with interface{}
	//@@ chaincodeCtorJSON (chaincode 생성시 msg) : --ctor, -c 플래그로 들어온 string 보관 
	//@@ JSON 으로 unmarshal 하여 "args", "function" 있는지 확인 --> 없으면 에러처리
	//@@ JSON 이 실제로 pb.ChaincodeInput 에 들어가고 나서, Type 검사가 수행됨
	if chaincodeCtorJSON != "{}" {
		var f interface{}
		err := json.Unmarshal([]byte(chaincodeCtorJSON), &f)
		if err != nil {
			return fmt.Errorf("Chaincode argument error: %s", err)
		}
		m := f.(map[string]interface{})
		sm := make(map[string]interface{})
		for k := range m {
			sm[strings.ToLower(k)] = m[k]
		}
		_, argsPresent := sm["args"]
		_, funcPresent := sm["function"]
		if !argsPresent || (len(m) == 2 && !funcPresent) || len(m) > 2 {
			return fmt.Errorf("Non-empty JSON chaincode parameters must contain the following keys: 'Args' or 'Function' and 'Args'")
		}
	} else {
		return errors.New("Empty JSON chaincode parameters must contain the following keys: 'Args' or 'Function' and 'Args'")
	}

	//@@ chaincodeAttributesJSON (chaincode attribute) : ----attributes, -a 플래그로 들어온 string 보관 
	//@@ JSON 으로 unmarshal --> 실패시 에러처리
	if chaincodeAttributesJSON != "[]" {
		var f interface{}
		err := json.Unmarshal([]byte(chaincodeAttributesJSON), &f)
		if err != nil {
			return fmt.Errorf("Chaincode argument error: %s", err)
		}
	}

	return nil
}
