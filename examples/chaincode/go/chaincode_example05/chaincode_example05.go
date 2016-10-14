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

package main

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/core/util"
)

// This chaincode is a test for chaincode querying another chaincode - invokes chaincode_example02 and computes the sum of a and b and stores it as state

// SimpleChaincode example simple Chaincode implementation
type SimpleChaincode struct {
}

// Init takes two arguments, a string and int. The string will be a key with
// the int as a value.
// 두개의 인풋 인자
// 1. string 타입의 key : 어카운트
// 2. int타입의 value : 자산수량.(sum of holdings)
func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	var sum string // Sum of asset holdings across accounts. Initially 0
	var sumVal int // Sum of holdings
	var err error

	if len(args) != 2 {
		return nil, errors.New("Incorrect number of arguments. Expecting 2")
	}

	// Initialize the chaincode
	// 체인코드 init
	sum = args[0]
	sumVal, err = strconv.Atoi(args[1])
	if err != nil {
		return nil, errors.New("Expecting integer value for sum")
	}
	fmt.Printf("sumVal = %d\n", sumVal)

	// Write the state to the ledger
	// 어카운트의 자산수량 상태를 렛저에 write
	err = stub.PutState(sum, []byte(strconv.Itoa(sumVal)))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

// Invoke queries another chaincode and updates its own state
// 다른 체인코드에 query를 수행하고, 본 체인코드의 상태를 갱신
func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	var sum string             // Sum entity
	var Aval, Bval, sumVal int // value of sum entity - to be computed
	var err error
	// 두개의 인풋 인자. 첫번째는 호출할 다른 체인코드 URL, 두번째는 수량
	if len(args) != 2 {
		return nil, errors.New("Incorrect number of arguments. Expecting 2")
	}

	chaincodeURL := args[0] // Expecting "github.com/hyperledger/fabric/core/example/chaincode/chaincode_example02"
	sum = args[1]

	// Query chaincode_example02
	// chaincode_example02 에 쿼리를 날림. -> A라는 엔티티를 인풋인자로 넘겨 현재 A의 자산 수량을 get
	f := "query"
	queryArgs := util.ToChaincodeArgs(f, "a")
	response, err := stub.QueryChaincode(chaincodeURL, queryArgs) //@@ 체인코드간의 calling은 QueryChaincode, InvokeChincode
	if err != nil {
		errStr := fmt.Sprintf("Failed to query chaincode. Got error: %s", err.Error())
		fmt.Printf(errStr)
		return nil, errors.New(errStr)
	}
	// chaincode_example02가 리턴하는 A엔티티의 현재 자산 수량은 Aval에 넣음
	Aval, err = strconv.Atoi(string(response))
	if err != nil {
		errStr := fmt.Sprintf("Error retrieving state from ledger for queried chaincode: %s", err.Error())
		fmt.Printf(errStr)
		return nil, errors.New(errStr)
	}
	//엔티티 B에 대해서도 A와 동일하게 현재의 자산 수량을 get
	queryArgs = util.ToChaincodeArgs(f, "b")
	response, err = stub.QueryChaincode(chaincodeURL, queryArgs)
	if err != nil {
		errStr := fmt.Sprintf("Failed to query chaincode. Got error: %s", err.Error())
		fmt.Printf(errStr)
		return nil, errors.New(errStr)
	}
	Bval, err = strconv.Atoi(string(response))
	if err != nil {
		errStr := fmt.Sprintf("Error retrieving state from ledger for queried chaincode: %s", err.Error())
		fmt.Printf(errStr)
		return nil, errors.New(errStr)
	}

	// Compute sum
	//@@ A와 B의 자산 수량을 합 (100 + 200 = 300)
	sumVal = Aval + Bval

	// Write sumVal back to the ledger
	// 자산의 총수량(A와 B를 합한)을 렛저에 기록
	err = stub.PutState(sum, []byte(strconv.Itoa(sumVal)))
	if err != nil {
		return nil, err
	}

	fmt.Printf("Invoke chaincode successful. Got sum %d\n", sumVal)
	return []byte(strconv.Itoa(sumVal)), nil
}

// Query callback representing the query of a chaincode
// @@ Query함수. --> chaincode_example02에 query를 날려 자산의 총합 수량을 구함
func (t *SimpleChaincode) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	if function != "query" {
		return nil, errors.New("Invalid query function name. Expecting \"query\"")
	}
	var sum string             // Sum entity
	var Aval, Bval, sumVal int // value of sum entity - to be computed
	var err error

	// Can query another chaincode within query, but cannot put state or invoke another chaincode (in transaction context)
	if len(args) != 2 {
		return nil, errors.New("Incorrect number of arguments. Expecting 2")
	}

	chaincodeURL := args[0]
	sum = args[1]

	// Query chaincode_example02
	f := "query"
	queryArgs := util.ToChaincodeArgs(f, "a")
	response, err := stub.QueryChaincode(chaincodeURL, queryArgs)
	if err != nil {
		errStr := fmt.Sprintf("Failed to query chaincode. Got error: %s", err.Error())
		fmt.Printf(errStr)
		return nil, errors.New(errStr)
	}
	Aval, err = strconv.Atoi(string(response))
	if err != nil {
		errStr := fmt.Sprintf("Error retrieving state from ledger for queried chaincode: %s", err.Error())
		fmt.Printf(errStr)
		return nil, errors.New(errStr)
	}

	queryArgs = util.ToChaincodeArgs(f, "b")
	response, err = stub.QueryChaincode(chaincodeURL, queryArgs)
	if err != nil {
		errStr := fmt.Sprintf("Failed to query chaincode. Got error: %s", err.Error())
		fmt.Printf(errStr)
		return nil, errors.New(errStr)
	}
	Bval, err = strconv.Atoi(string(response))
	if err != nil {
		errStr := fmt.Sprintf("Error retrieving state from ledger for queried chaincode: %s", err.Error())
		fmt.Printf(errStr)
		return nil, errors.New(errStr)
	}

	// Compute sum
	sumVal = Aval + Bval

	fmt.Printf("Query chaincode successful. Got sum %d\n", sumVal)
	jsonResp := "{\"Name\":\"" + sum + "\",\"Value\":\"" + strconv.Itoa(sumVal) + "\"}"
	fmt.Printf("Query Response:%s\n", jsonResp)
	return []byte(strconv.Itoa(sumVal)), nil
}

func main() {
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Printf("Error starting Simple chaincode: %s", err)
	}
}
