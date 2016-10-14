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

//WARNING - this chaincode's ID is hard-coded in chaincode_example04 to illustrate one way of
//calling chaincode from a chaincode. If this example is modified, chaincode_example04.go has
//to be modified as well with the new ID of chaincode_example02.
//chaincode_example05 show's how chaincode ID can be passed in as a parameter instead of
//hard-coding.

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/hyperledger/fabric/core/chaincode/shim"
)

// EventSender example simple Chaincode implementation
// 이벤트를 송신하는 간단한 체인코드 예제.
type EventSender struct {
}

// Init function
// 체인코드 init상태는 noevents라는 키는 value 0으로 셋팅
func (t *EventSender) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	err := stub.PutState("noevents", []byte("0"))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

// Invoke function
// 체인코드 실행 invoke는 현재의 상태를 확인 -> (noevents,  0)
// 변경된 상태를 기록하고 -> (noevents, 1)
// stub.SetEvent함수를 이용하여 noevents의 변화를 이벤트("evtsender")에 등록 저장.
func (t *EventSender) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	b, err := stub.GetState("noevents") // Init이후 b = 0
	if err != nil {
		return nil, errors.New("Failed to get state")
	}
	noevts, _ := strconv.Atoi(string(b))

	tosend := "Event " + string(b)
	for _, s := range args {
		tosend = tosend + "," + s // tosend= Event 0 , 1 ?
	}
	// noevents의 상태를 변경
	err = stub.PutState("noevents", []byte(strconv.Itoa(noevts+1))) //(noevents, 1)?
	if err != nil {
		return nil, err
	}
	// shim interface : setEvent saves the event to be sent when a transaction is made part of a block
	// SetEvent(name string, payload []byte) error
	// 이 체인코드 실행 트랜잭션에 블록에 산입될 때 발생할 이벤트를 evtsender로 등록 저장.
	err = stub.SetEvent("evtsender", []byte(tosend))
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// Query function
func (t *EventSender) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	b, err := stub.GetState("noevents")
	if err != nil {
		return nil, errors.New("Failed to get state")
	}
	jsonResp := "{\"NoEvents\":\"" + string(b) + "\"}"
	return []byte(jsonResp), nil
}

func main() {
	err := shim.Start(new(EventSender))
	if err != nil {
		fmt.Printf("Error starting EventSender chaincode: %s", err)
	}
}
