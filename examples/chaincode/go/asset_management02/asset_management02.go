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
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/op/go-logging"
)

var myLogger = logging.MustGetLogger("asset_mgm")

var cHandler = NewCertHandler()
var dHandler = NewDepositoryHandler()

//AssetManagementChaincode APIs exposed to chaincode callers
type AssetManagementChaincode struct {
}

// assignOwnership assigns assets to a given account ID, only entities with the "issuer" are allowed to call this function
// Note: this issuer can only allocate balance to one account ID at a time
// args[0]: investor's TCert
// args[1]: attribute name inside the investor's TCert that contains investor's account ID
// args[2]: amount to be assigned to this investor's account ID
// @@ assignOwnership은 주어진 accountID에 자산을 배정하는데. 오직 issuer만이 이를 실행할 권한이 있다.
// @@ 인풋 인자는 순서대로 투자자의 tcert,
// @@ 투자자의 accountID를 포함하는 투자자 Tcert의 attribute name,
// @@ 투자자의 accountID로 배정될 자산의 수량
func (t *AssetManagementChaincode) assignOwnership(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	myLogger.Debugf("+++++++++++++++++++++++++++++++++++assignOwnership+++++++++++++++++++++++++++++++++")

	if len(args) != 3 {
		return nil, errors.New("Incorrect number of arguments. Expecting 0")
	}

	//check is invoker has the correct role, only invokers with the "issuer" role is allowed to
	//assign asset to owners
	//@@ 체인코드 실행자가 자산발행자로서 투자자에게 자산을 배정할 권한이 있는지를 체크
	isAuthorized, err := cHandler.isAuthorized(stub, "issuer")
	if !isAuthorized {
		myLogger.Errorf("system error %v", err)
		return nil, errors.New("user is not aurthorized to assign assets")
	}
	//체인코드 실행자가 자산발행자라면(즉, 권한이 있다면) 투자자의 tcert를 decode
	owner, err := base64.StdEncoding.DecodeString(args[0])
	if err != nil {
		myLogger.Errorf("system error %v", err)
		return nil, errors.New("Failed decoding owner")
	}
	accountAttribute := args[1]

	amount, err := strconv.ParseUint(args[2], 10, 64)
	if err != nil {
		myLogger.Errorf("system error %v", err)
		return nil, errors.New("Unable to parse amount" + args[2])
	}

	//retrieve account IDs from investor's TCert
	//@@ 투자자의 tcert로부터 accountID를 get
	accountIDs, err := cHandler.getAccountIDsFromAttribute(owner, []string{accountAttribute})
	if err != nil {
		myLogger.Errorf("system error %v", err)
		return nil, errors.New("Unable to retrieve account Ids from user certificate " + args[1])
	}

	//retreive investors' contact info (e.g. phone number, email, home address)
	//from investors' TCert. Ideally, this information shall be encrypted with issuer's pub key or KA key
	//between investor and issuer, so that only issuer can view such information
	//투자자의 tcert의 attribute에 저장된 contact info를 get
	//이상적으로는, 발행자만이 이러한 정보를 볼수 있도록,
	//해당 정보들은 자산 발행자(issuer)의 공개키 또는 투자자와 발행자간의 KA키로 암호화되어 있어야 함.

	contactInfo, err := cHandler.getContactInfo(owner)
	if err != nil {
		return nil, errors.New("Unable to retrieve contact info from user certificate " + args[1])
	}

	//call DeposistoryHandler.assign function to put the "amount" and "contact info" under this account ID
	//@@ DeposistoryHandler.assign을 호출하여 자산 수량과, 연락처정보를 투자자의 accountID에 저장.
	return nil, dHandler.assign(stub, accountIDs[0], contactInfo, amount)
}

// transferOwnership moves x number of assets from account A to account B
// args[0]: Investor TCert that has account IDs which will their balances deducted
// args[1]: attribute names inside TCert (arg[0]) that countain the account IDs
// args[2]: Investor TCert that has account IDs which will have their balances increased
// args[3]: attribute names inside TCert (arg[2]) that countain the account IDs
// transferOwnership : 자산 X 수량을 A의 어카운트에서 B의 어카운트로 이체.
// 인풋 0 : 투자자의 Tcert, 자산을 이체함에 따라 이 투자자의 잔고는 차감 될 것. --> A
// 인풋 1 : 투자자의 account id를 포함하는 투자자의 tcert의 attribute name --> A's
// 인풋 2 : 투자자의 Tcert, 자산을 수령함에 따라 이 투자자의 잔고는 증가 될 것. --> B
// 인풋 3 : 투자자의 account id를 포함하는 투자자의 tcert의 attribute name --> B's
// 인풋 4 : A로부터 B로 이체될 자산 수량
func (t *AssetManagementChaincode) transferOwnership(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	myLogger.Debugf("+++++++++++++++++++++++++++++++++++transferOwnership+++++++++++++++++++++++++++++++++")

	if len(args) != 5 {
		return nil, errors.New("Incorrect number of arguments. Expecting 0")
	}
	// A의 tcert를 decode
	fromOwner, err := base64.StdEncoding.DecodeString(args[0])
	if err != nil {
		myLogger.Errorf("system error %v", err)
		return nil, errors.New("Failed decoding fromOwner")
	}
	fromAccountAttributes := strings.Split(args[1], ",")
	// B의 tcert를 decode
	toOwner, err := base64.StdEncoding.DecodeString(args[2])
	if err != nil {
		myLogger.Errorf("system error %v", err)
		return nil, errors.New("Failed decoding owner")
	}
	toAccountAttributes := strings.Split(args[3], ",")
	// 이체되어야할 자산 수량
	amount, err := strconv.ParseUint(args[4], 10, 64)
	if err != nil {
		myLogger.Errorf("system error %v", err)
		return nil, errors.New("Unable to parse amount" + args[4])
	}

	// retrieve account IDs from "transfer from" TCert
	// 이체를 하는, 즉 자산이 차감될 투자자의 account id를 get
	fromAccountIds, err := cHandler.getAccountIDsFromAttribute(fromOwner, fromAccountAttributes)
	if err != nil {
		myLogger.Errorf("system error %v", err)
		return nil, errors.New("Unable to retrieve contact info from user certificate" + args[1])
	}

	// retrieve account IDs from "transfer to" TCert
	// 이체를 받는, 즉 자산이 증가될 투자자의 account id를 get
	toAccountIds, err := cHandler.getAccountIDsFromAttribute(toOwner, toAccountAttributes)
	if err != nil {
		myLogger.Errorf("system error %v", err)
		return nil, errors.New("Unable to retrieve contact info from user certificate" + args[3])
	}

	// retrieve contact info from "transfer to" TCert
	// 이체를 받는, 즉 자산이 증가될 투자자의 연락처 정보를 get
	contactInfo, err := cHandler.getContactInfo(toOwner)
	if err != nil {
		myLogger.Errorf("system error %v received", err)
		return nil, errors.New("Unable to retrieve contact info from user certificate" + args[4])
	}

	// call dHandler.transfer to transfer to transfer "amount" from "from account" IDs to "to account" IDs
	// depository 핸들러의 transfer를 호출하여, 이체를 실행
	return nil, dHandler.transfer(stub, fromAccountIds, toAccountIds[0], contactInfo, amount)
}

// getOwnerContactInformation retrieves the contact information of the investor that owns a particular account ID
// Note: user contact information shall be encrypted with issuer's pub key or KA key
// between investor and issuer, so that only issuer can decrypt such information
// args[0]: one of the many account IDs owned by "some" investor
//@@ getOwnerContactInformation : 투자자의 accountid를 입력받아 해당 투자자의 cert에서 연락처 정보를 추출
//@@ 내부적으로 depository handler를 호출
func (t *AssetManagementChaincode) getOwnerContactInformation(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	myLogger.Debugf("+++++++++++++++++++++++++++++++++++getOwnerContactInformation+++++++++++++++++++++++++++++++++")

	if len(args) != 1 {
		return nil, errors.New("Incorrect number of arguments. Expecting 0")
	}

	accountID := args[0]

	email, err := dHandler.queryContactInfo(stub, accountID)
	if err != nil {
		return nil, err
	}

	return []byte(email), nil
}

// getBalance retrieves the account balance information of the investor that owns a particular account ID
// args[0]: one of the many account IDs owned by "some" investor
func (t *AssetManagementChaincode) getBalance(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	myLogger.Debugf("+++++++++++++++++++++++++++++++++++getBalance+++++++++++++++++++++++++++++++++")

	if len(args) != 1 {
		return nil, errors.New("Incorrect number of arguments. Expecting 0")
	}

	accountID := args[0]

	balance, err := dHandler.queryBalance(stub, accountID)
	if err != nil {
		return nil, err
	}

	//convert balance (uint64) to []byte (Big Endian)
	ret := make([]byte, 8)
	binary.BigEndian.PutUint64(ret, balance)

	return ret, nil
}

// Init initialization, this method will create asset despository in the chaincode state
// Init는. asset depository 테이블을 생성하고, 초기값을 셋팅한다.
// 내부적으로 depository 핸들러에 의해서 수행된다
func (t *AssetManagementChaincode) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	myLogger.Debugf("********************************Init****************************************")

	myLogger.Info("[AssetManagementChaincode] Init")
	if len(args) != 0 {
		return nil, errors.New("Incorrect number of arguments. Expecting 0")
	}

	return nil, dHandler.createTable(stub)
}

// Invoke  method is the interceptor of all invocation transactions, its job is to direct
// invocation transactions to intended APIs
// Invoke는 내부적으로 assignOwnership, transferOwnership을 호출하여 자산 배정과 자산 이체를 처리.
// 각 서브 펑션들도 내부적으로는  depository 핸들러에 의해서 수행된다
func (t *AssetManagementChaincode) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	myLogger.Debugf("********************************Invoke****************************************")

	//	 Handle different functions
	if function == "assignOwnership" {
		// Assign ownership
		return t.assignOwnership(stub, args)
	} else if function == "transferOwnership" {
		// Transfer ownership
		return t.transferOwnership(stub, args)
	}

	return nil, errors.New("Received unknown function invocation")
}

// Query method is the interceptor of all invocation transactions, its job is to direct
// query transactions to intended APIs, and return the result back to callers
// Query는 내부적으로 자산소유자의 연락처정보를 구하는 getOwnerContactInformation,
// 계좌의 잔고를 조회하는 getBalance, 이 두 개의 함수로 이루어져 있으며, 그 결과를 함수 호출자에게 리턴한다.
func (t *AssetManagementChaincode) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	myLogger.Debugf("********************************Query****************************************")

	// Handle different functions
	if function == "getOwnerContactInformation" {
		return t.getOwnerContactInformation(stub, args)
	} else if function == "getBalance" {
		return t.getBalance(stub, args)
	}

	return nil, errors.New("Received unknown function query invocation with function " + function)
}

// 체인코드 실행 main
func main() {

	//	primitives.SetSecurityLevel("SHA3", 256)
	err := shim.Start(new(AssetManagementChaincode))
	if err != nil {
		myLogger.Debugf("Error starting AssetManagementChaincode: %s", err)
	}

}
