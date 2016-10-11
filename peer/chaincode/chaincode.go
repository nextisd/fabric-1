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

	"github.com/hyperledger/fabric/peer/common"
	"github.com/op/go-logging"
	"github.com/spf13/cobra"
)

const (
	chainFuncName = "chaincode"
)

var logger = logging.MustGetLogger("chaincodeCmd")

// Cmd returns the cobra command for Chaincode
//@@ chaincode command 에 대한 플래그 값을 전역변수에 세팅
//@@ chaincode command 에 (deploy, invoke, query) command add
//@@ 여기 옵션 사용예 : "peer chaincode --lang golang"
//@@ chaincodeLang			: --lang, -l 플래그 값, default = "golang"
//@@ chaincodeCtorJSON		: --ctor, -c 플래그 값,  default = "{}"
//@@ chaincodeAttributesJSON	: --attributes, -a 플래그 값,  default = "[]"
//@@ chaincodePath			: --path, -p 플래그 값,  default = ""
//@@ chaincodeName			: --name, -n 플래그 값,  default = ""
//@@ chaincodeUsr			: --username, -u 플래그 값,  default = ""
//@@ customIDGenAlg			: --tid, -t 플래그 값,  default = ""
dd
  -a, --attributes string   User attributes for the chaincode in JSON format (default "[]")
  -c, --ctor string         Constructor message for the chaincode in JSON format (default "{}")
  -l, --lang string         Language the chaincode is written in (default "golang")
  -n, --name string         Name of the chaincode returned by the deploy transaction
  -p, --path string         Path to chaincode
  -t, --tid string          Name of a custom ID generation algorithm (hashing and decoding) e.g. sha256base64
  -u, --username string     Username for chaincode operations when security is enabled

func Cmd() *cobra.Command {
	flags := chaincodeCmd.PersistentFlags()

	//@@ chaincodeLang : --lang 또는 -l 플래그값, default = "golang", usage func. = Sprintf
		flags.StringVarP(&chaincodeLang, "lang", "l", "golang",
		fmt.Sprintf("Language the %s is written in", chainFuncName))
	flags.StringVarP(&chaincodeCtorJSON, "ctor", "c", "{}",
		fmt.Sprintf("Constructor message for the %s in JSON format", chainFuncName))
	flags.StringVarP(&chaincodeAttributesJSON, "attributes", "a", "[]",
		fmt.Sprintf("User attributes for the %s in JSON format", chainFuncName))
	flags.StringVarP(&chaincodePath, "path", "p", common.UndefinedParamValue,
		fmt.Sprintf("Path to %s", chainFuncName))
	flags.StringVarP(&chaincodeName, "name", "n", common.UndefinedParamValue,
		fmt.Sprint("Name of the chaincode returned by the deploy transaction"))
	flags.StringVarP(&chaincodeUsr, "username", "u", common.UndefinedParamValue,
		fmt.Sprint("Username for chaincode operations when security is enabled"))
	flags.StringVarP(&customIDGenAlg, "tid", "t", common.UndefinedParamValue,
		fmt.Sprint("Name of a custom ID generation algorithm (hashing and decoding) e.g. sha256base64"))

	chaincodeCmd.AddCommand(deployCmd())
	chaincodeCmd.AddCommand(invokeCmd())
	chaincodeCmd.AddCommand(queryCmd())

	return chaincodeCmd
}

// Chaincode-related variables.
//@@ chaincode command, flags 를 저장하는 전역변수
var (
	chaincodeLang           string
	chaincodeCtorJSON       string
	chaincodePath           string
	chaincodeName           string
	chaincodeUsr            string
	chaincodeQueryRaw       bool
	chaincodeQueryHex       bool
	chaincodeAttributesJSON string
	customIDGenAlg          string
)

var chaincodeCmd = &cobra.Command{
	Use:   chainFuncName,
	Short: fmt.Sprintf("%s specific commands.", chainFuncName),
	Long:  fmt.Sprintf("%s specific commands.", chainFuncName),
}
