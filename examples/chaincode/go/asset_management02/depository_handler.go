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

	"github.com/hyperledger/fabric/core/chaincode/shim"
)

// consts associated with chaincode table
const (
	tableColumn       = "AssetsOwnership"
	columnAccountID   = "Account"
	columnContactInfo = "ContactInfo"
	columnAmount      = "Amount"
)

//DepositoryHandler provides APIs used to perform operations on CC's KV store
// depositoryHandler : 체인코드의 key value 스토어에 특정 오퍼레이션을 수행하는 api를 제공.
type depositoryHandler struct {
}

// NewDepositoryHandler create a new reference to CertHandler
// CertHandler에 대한 새로운 참조 링크를 생성
func NewDepositoryHandler() *depositoryHandler {
	return &depositoryHandler{}
}

// createTable initiates a new asset depository table in the chaincode state
// stub: chaincodestub
// createTable : 새로운 자산 depository 테이블을 체인코드 상태에 생성. -> shim.ColumnDefinition이용.
func (t *depositoryHandler) createTable(stub shim.ChaincodeStubInterface) error {

	// Create asset depository table
	return stub.CreateTable(tableColumn, []*shim.ColumnDefinition{
		&shim.ColumnDefinition{Name: columnAccountID, Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: columnContactInfo, Type: shim.ColumnDefinition_STRING, Key: false},
		&shim.ColumnDefinition{Name: columnAmount, Type: shim.ColumnDefinition_UINT64, Key: false},
	})

}

// assign allocates assets to account IDs in the chaincode state for each of the
// account ID passed in.
// accountID: account ID to be allocated with requested amount
// contactInfo: contact information of the owner of the account ID passed in
// amount: amount to be allocated to this account ID
// @@ assign : 체인코드를 통해 입력된 accountid에 자산을 배정한다.
// @@ 입력인자 0 : account id -> 요청 수량만큼 자산을 수령할 계좌
// @@ 입력인자 1 : contact info -> 계좌 소유자의 연락처 정보
// @@ 입력인자 2 : amount -> 계좌에 배정될 자산 수량
func (t *depositoryHandler) assign(stub shim.ChaincodeStubInterface,
	accountID string,
	contactInfo string,
	amount uint64) error {

	myLogger.Debugf("insert accountID= %v", accountID)

	//insert a new row for this account ID that includes contact information and balance
	// 테이블(asset depository table)에 새로운 row를 insert
	// key = account id, value = contact info, balance
	ok, err := stub.InsertRow(tableColumn, shim.Row{
		Columns: []*shim.Column{
			&shim.Column{Value: &shim.Column_String_{String_: accountID}},
			&shim.Column{Value: &shim.Column_String_{String_: contactInfo}},
			&shim.Column{Value: &shim.Column_Uint64{Uint64: amount}}},
	})

	// you can only assign balances to new account IDs
	// 새로운 account id만 수량을 배정할 수 있다. 기존에 있는 account id에는 잔고 배정 X
	if !ok && err == nil {
		myLogger.Errorf("system error %v", err)
		return errors.New("Asset was already assigned.")
	}

	return nil
}

// updateAccountBalance updates the balance amount of an account ID
// stub: chaincodestub
// accountID: account will be updated with the new balance
// contactInfo: contact information associated with the account owner (chaincode table does not allow me to perform updates on specific columns)
// amount: new amount to be udpated with
// @@ updateAccountBalance : 해당하는 account의 잔고 상태를 갱신한다.

func (t *depositoryHandler) updateAccountBalance(stub shim.ChaincodeStubInterface,
	accountID string,
	contactInfo string,
	amount uint64) error {

	myLogger.Debugf("insert accountID= %v", accountID)

	//replace the old record row associated with the account ID with the new record row
	//@@ 입력받은 accountid에 해당하는 새로이 갱신된 데이터를 insert하고, 기존 row를 삭제한다. -> replacerow
	ok, err := stub.ReplaceRow(tableColumn, shim.Row{
		Columns: []*shim.Column{
			&shim.Column{Value: &shim.Column_String_{String_: accountID}},
			&shim.Column{Value: &shim.Column_String_{String_: contactInfo}},
			&shim.Column{Value: &shim.Column_Uint64{Uint64: amount}}},
	})

	if !ok && err == nil {
		myLogger.Errorf("system error %v", err)
		return errors.New("failed to replace row with account Id." + accountID)
	}
	return nil
}

// deleteAccountRecord deletes the record row associated with an account ID on the chaincode state table
// stub: chaincodestub
// accountID: account ID (record matching this account ID will be deleted after calling this method)
// @@ deleteAccountRecord : 입력된 account에 해당하는 데이터 row를 테이블에서 삭제 한다.
func (t *depositoryHandler) deleteAccountRecord(stub shim.ChaincodeStubInterface, accountID string) error {

	myLogger.Debugf("insert accountID= %v", accountID)

	//delete record matching account ID passed in
	err := stub.DeleteRow(
		"AssetsOwnership",
		[]shim.Column{shim.Column{Value: &shim.Column_String_{String_: accountID}}},
	)

	if err != nil {
		myLogger.Errorf("system error %v", err)
		return errors.New("error in deleting account record")
	}
	return nil
}

// transfer transfers X amount of assets from "from account IDs" to a new account ID
// stub: chaincodestub
// fromAccounts: from account IDs with assets to be transferred
// toAccount: a new account ID on the table that will get assets transfered to
// toContact: contact information of the owner of "to account ID"
// @@ X수량의 자산을 fromAccounts로부터 toAccount로 이체. toContact는 자산을 이체 받는 자의 연락처 정보.
func (t *depositoryHandler) transfer(stub shim.ChaincodeStubInterface, fromAccounts []string, toAccount string, toContact string, amount uint64) error {

	myLogger.Debugf("insert params= %v , %v , %v , %v ", fromAccounts, toAccount, toContact, amount)

	//collecting assets need to be transfered
	//복수개의 accounts에서 이체될 자산을 모은다. --> acctBalance
	remaining := amount //이체대상수량 == remaining
	for i := range fromAccounts {
		contactInfo, acctBalance, err := t.queryAccount(stub, fromAccounts[i])
		if err != nil {
			myLogger.Errorf("system error %v", err)
			return errors.New("error in deleting account record")
		}

		if remaining > 0 {
			//check if this account need to be spent entirely; if so, delete the
			//account record row, otherwise just take out what' needed
			//1. 이체할 자산 수량이 모든 계좌의 잔고의 합보다 크거나 같다면, 이체되어야할 수량(remaining)에서 현재의 잔고수량 합을 뺀다.
			if remaining >= acctBalance {
				remaining -= acctBalance
				//delete accounts with 0 balance, this step is optional
				//이체로 인해서 잔고가 0이 되면, 해당 계좌는 삭제한다(optional)
				t.deleteAccountRecord(stub, fromAccounts[i])
			} else { // 2. 이체할 자산 수량이 모든 계좌의 잔고의 합보다 작다면, 잔고의 합에서 이체되어야할 수량을 뺀다.
				acctBalance -= remaining
				remaining = 0 //이체 완료.
				//수량이 남은 해당 계좌(fromAccounts[i])의 잔고를 갱신
				t.updateAccountBalance(stub, fromAccounts[i], contactInfo, acctBalance)
				break
			}
		}
	}

	//check if toAccount already exist
	//이체를 수신할 계좌(toAccount)가 기존재하는지 여부를 확인, 존재하면 에러
	acctBalance, err := t.queryBalance(stub, toAccount)
	if err == nil || acctBalance > 0 {
		myLogger.Errorf("system error %v", err)
		return errors.New("error in deleting account record")
	}

	//create new toAccount in the Chaincode state table, and assign the total amount
	//to its balance
	//@@ 새로운 toAccount를 생성하고, toAccount로 자산 수량을 배정한다.
	return t.assign(stub, toAccount, toContact, amount)

}

// queryContactInfo queries the contact information matching a correponding account ID on the chaincode state table
// stub: chaincodestub
// accountID: account ID
// queryContactInfo : 매칭되는 accountID에 해당하는 연락처 정보를 table에서 get
func (t *depositoryHandler) queryContactInfo(stub shim.ChaincodeStubInterface, accountID string) (string, error) {
	row, err := t.queryTable(stub, accountID)
	if err != nil {
		return "", err
	}

	return row.Columns[1].GetString_(), nil
}

// queryBalance queries the balance information matching a correponding account ID on the chaincode state table
// stub: chaincodestub
// accountID: account ID
// queryBalance : 매칭되는 accountID에 해당하는 계좌 잔고 정보를 get
func (t *depositoryHandler) queryBalance(stub shim.ChaincodeStubInterface, accountID string) (uint64, error) {

	myLogger.Debugf("insert accountID= %v", accountID)

	row, err := t.queryTable(stub, accountID)
	if err != nil {
		return 0, err
	}
	if len(row.Columns) == 0 || row.Columns[2] == nil {
		return 0, errors.New("row or column value not found")
	}

	return row.Columns[2].GetUint64(), nil
}

// queryAccount queries the balance and contact information matching a correponding account ID on the chaincode state table
// stub: chaincodestub
// accountID: account ID
// @@ queryAccount: 매칭되는 accountID에 해당하는 계좌의 잔고와 연락처 정보를 get
func (t *depositoryHandler) queryAccount(stub shim.ChaincodeStubInterface, accountID string) (string, uint64, error) {
	row, err := t.queryTable(stub, accountID)
	if err != nil {
		return "", 0, err
	}
	if len(row.Columns) == 0 || row.Columns[2] == nil {
		return "", 0, errors.New("row or column value not found")
	}

	return row.Columns[1].GetString_(), row.Columns[2].GetUint64(), nil
}

// queryTable returns the record row matching a correponding account ID on the chaincode state table
// stub: chaincodestub
// accountID: account ID
// @@ queryTable : accountID를 key로 가진 데이터 row를 체인코드 상태 테이블에서 get
func (t *depositoryHandler) queryTable(stub shim.ChaincodeStubInterface, accountID string) (shim.Row, error) {

	var columns []shim.Column
	col1 := shim.Column{Value: &shim.Column_String_{String_: accountID}}
	columns = append(columns, col1)

	return stub.GetRow(tableColumn, columns)
}
