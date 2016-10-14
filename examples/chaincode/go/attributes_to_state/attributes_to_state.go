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

	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/core/chaincode/shim/crypto/attr"
)

// Attributes2State demonstrates how to read attributes from TCerts.
//@@ Attributes2State는 Tcert에서 attribute를 읽어오는 것을 demo.
type Attributes2State struct {
}

//@@ Init 시점(deploy)에 초기 attribute와 상태를 기록. Init함수에 의해 콜링됨.
func (t *Attributes2State) setStateToAttributes(stub shim.ChaincodeStubInterface, args []string) error {
	attrHandler, err := attr.NewAttributesHandlerImpl(stub)
	if err != nil {
		return err
	}
	for _, att := range args {
		fmt.Println("Writing attribute " + att)
		attVal, err := attrHandler.GetValue(att)
		if err != nil {
			return err
		}
		//렛저에 attibute를 기록
		err = stub.PutState(att, attVal)
		if err != nil {
			return err
		}
	}
	return nil
}

// Init intializes the chaincode by reading the transaction attributes and storing
// the attrbute values in the state
//@@ Init : 트랜잭션 attributes를 읽고 해당 attribute의 value를 state에 저장하여 체인코드를 초기화
func (t *Attributes2State) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	err := t.setStateToAttributes(stub, args)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// Invoke takes two arguements, a key and value, and stores these in the state
//@@ Invoke함수는 키와 value값을 받아서 state에 저장한다.
//@@ 동작 펑션은 attirbute 삭제인 delete와 submit 두가지가 있다.
//@@ submit의 구현은 어디?
func (t *Attributes2State) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	if function == "delete" {
		return nil, t.delete(stub, args)
	}

	if function != "submit" {
		return nil, errors.New("Invalid invoke function name. Expecting either \"delete\" or \"submit\"")
	}
	err := t.setStateToAttributes(stub, args)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// delete Deletes an entity from the state, returning error if the entity was not found in the state.
//@@ delete 펑션은 아규먼트로 attribute를 받아서 해당 attribute가 state렛저에 존재한다면, 지운다.(stub.DelState)
func (t *Attributes2State) delete(stub shim.ChaincodeStubInterface, args []string) error {
	if len(args) != 1 {
		return errors.New("Incorrect number of arguments. Expecting only 1 (attributeName)")
	}

	attributeName := args[0]
	fmt.Printf("Deleting attribute %v", attributeName)
	valBytes, err := stub.GetState(attributeName)
	if err != nil {
		return err
	}

	if valBytes == nil {
		return errors.New("Attribute '" + attributeName + "' not found.")
	}

	isOk, err := stub.VerifyAttribute(attributeName, valBytes)
	if err != nil {
		return err
	}
	if isOk {
		// Delete the key from the state in ledger
		err = stub.DelState(attributeName)
		if err != nil {
			return errors.New("Failed to delete state")
		}
	}
	return nil
}

// Query callback representing the query of a chaincode
// @@ 쿼리 함수는 attribute를 입력 받아, state 렛저에서 현재 상태를 확인하고 그 상태를 리턴.
func (t *Attributes2State) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	if function != "read" {
		return nil, errors.New("Invalid query function name. Expecting \"read\"")
	}
	var attributeName string // Name of the attributeName to query.
	var err error

	if len(args) != 1 {
		return nil, errors.New("Incorrect number of arguments. Expecting only 1 (attributeName)")
	}

	attributeName = args[0]
	fmt.Printf("Reading attribute %v", attributeName)

	// Get the state from the ledger
	Avalbytes, err := stub.GetState(attributeName)
	if err != nil {
		jsonResp := "{\"Error\":\"Failed to get state for " + attributeName + "\"}"
		fmt.Printf("Query Response:%s\n", jsonResp)
		return nil, errors.New(jsonResp)
	}

	if Avalbytes == nil {
		jsonResp := "{\"Error\":\"Nil amount for " + attributeName + "\"}"
		fmt.Printf("Query Response:%s\n", jsonResp)
		return nil, errors.New(jsonResp)
	}

	jsonResp := "{\"Name\":\"" + attributeName + "\",\"Amount\":\"" + string(Avalbytes) + "\"}"
	fmt.Printf("Query Response:%s\n", jsonResp)
	return []byte(jsonResp), nil
}

// 체인코드의 실행을 지시하는 메인함수.
func main() {
	err := shim.Start(new(Attributes2State))
	if err != nil {
		fmt.Printf("Error running Attributes2State chaincode: %s", err)
	}
}
