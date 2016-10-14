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
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/core/chaincode/shim/crypto/attr"
	"github.com/op/go-logging"
)

var myLogger = logging.MustGetLogger("asset_mgm")

// AssetManagementChaincode example simple Asset Management Chaincode implementation
// with access control enforcement at chaincode level.
//
// This example implements asset transfer using attributes support and specifically Attribute Based Access Control (ABAC).
// There are three users in this example:
// - alice
// - bob
// - admin
//
// This users are defined in the section "eca" of asset.yaml file.
// In the section "aca" of asset.yaml file two attributes are defined to this users:
// The first attribute is called 'role' with this values:
// - alice has role = client
// - bob has role = client
// - admin has role = assigner
//
// The second attribute is called 'account' with this values:
// - alice has account = 12345-56789
// - bob has account = 23456-67890
//
// In the present example only users with role 'assigner' can associate an 'asset' as is implemented in function 'assign' and
// user with role 'client' can transfers theirs assets to other clients as is implemented in function 'transfer'.
// Asset ownership is stored in the ledger state and is linked to the client account.
// Attribute 'account' is used to associate transaction certificates with account owner.

//@@ AssetManagementChaincode : access control이 포함된 자산관리 체인코드 예시
//@@ attributes support를 이용한 자산 이체
//@@ 세 명의 유저 alice, bob, admin이 이 예시에서 액션을 취함.
//@@ asset.yaml의 aca영역에 롤과 어카운트 정보가 기재되어 있음.
//@@ 롤별 액션은 다음과 같이 한정
//@@ 1.assigner : 펑션 assign 에 대한 권한을 지님
//@@ 2.client : 펑션 transfer에 대한 권한을 지님
//@@ 자산의 소유권은 클라이언트 어카운트에 연결된 렛저 스테이트에 기록되어 있음.
//@@ 어카운트라는 attribute는 트랜잭션 cert와 어카운트 소유자의 연결 고리.

type AssetManagementChaincode struct {
}

// Init initialization
//@@ deploy시 초기화 함수.
func (t *AssetManagementChaincode) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	myLogger.Info("[AssetManagementChaincode] Init")
	if len(args) != 0 {
		return nil, errors.New("Incorrect number of arguments. Expecting 0")
	}

	// Create ownership table
	// 자산 소유권한을 columndefinition으로 정의.
	// table name : AssetsOwnership,
	// key : Asset, value : owner
	err := stub.CreateTable("AssetsOwnership", []*shim.ColumnDefinition{
		&shim.ColumnDefinition{Name: "Asset", Type: shim.ColumnDefinition_STRING, Key: true},
		&shim.ColumnDefinition{Name: "Owner", Type: shim.ColumnDefinition_BYTES, Key: false},
	})
	if err != nil {
		return nil, fmt.Errorf("Failed creating AssetsOnwership table, [%v]", err)
	}

	// Set the role of the users that are allowed to assign assets
	// The metadata will contain the role of the users that are allowed to assign assets
	// 자산을 배정하는 권한을 설정 -> 메타데이터가 이 내용을 포함하므로 GetCallerMetadata를 호출하여 권한 확인
	assignerRole, err := stub.GetCallerMetadata()
	fmt.Printf("Assiger role is %v\n", string(assignerRole))

	if err != nil {
		return nil, fmt.Errorf("Failed getting metadata, [%v]", err)
	}

	if len(assignerRole) == 0 {
		return nil, errors.New("Invalid assigner role. Empty.")
	}

	stub.PutState("assignerRole", assignerRole)

	return nil, nil
}

// 자산 배정 함수
func (t *AssetManagementChaincode) assign(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	fmt.Println("Assigning Asset...")

	if len(args) != 2 {
		return nil, errors.New("Incorrect number of arguments. Expecting 2")
	}

	asset := args[0]
	owner, err := base64.StdEncoding.DecodeString(args[1])
	if err != nil {
		fmt.Printf("Error decoding [%v] \n", err)
		return nil, errors.New("Failed decodinf owner")
	}

	// Recover the role that is allowed to make assignments
	// 자산 배정 권한을 가진 롤을 불러 옴.
	assignerRole, err := stub.GetState("assignerRole")
	if err != nil {
		fmt.Printf("Error getting role [%v] \n", err)
		return nil, errors.New("Failed fetching assigner role")
	}
	// 체인코드 호출자(caller)의 cert를 확인
	callerRole, err := stub.ReadCertAttribute("role")
	if err != nil {
		fmt.Printf("Error reading attribute 'role' [%v] \n", err)
		return nil, fmt.Errorf("Failed fetching caller role. Error was [%v]", err)
	}
	// 함수 호출자와 자산 배정 권한자 set
	caller := string(callerRole[:])
	assigner := string(assignerRole[:])
	// 만약 호출자가 자산 배정 권한자가 아니라면, 에러 발생
	if caller != assigner {
		fmt.Printf("Caller is not assigner - caller %v assigner %v\n", caller, assigner)
		return nil, fmt.Errorf("The caller does not have the rights to invoke assign. Expected role [%v], caller role [%v]", assigner, caller)
	}
	// 해당 자산의 어카운트 소유자가 아니라면, 에러 발생
	account, err := attr.GetValueFrom("account", owner)
	if err != nil {
		fmt.Printf("Error reading account [%v] \n", err)
		return nil, fmt.Errorf("Failed fetching recipient account. Error was [%v]", err)
	}

	// Register assignment
	// AssetOwnership 테이블에 자산과 자산 어카운트를 insert
	myLogger.Debugf("New owner of [%s] is [% x]", asset, owner)

	ok, err := stub.InsertRow("AssetsOwnership", shim.Row{
		Columns: []*shim.Column{
			&shim.Column{Value: &shim.Column_String_{String_: asset}},
			&shim.Column{Value: &shim.Column_Bytes{Bytes: account}}},
	})

	if !ok && err == nil {
		fmt.Println("Error inserting row")
		return nil, errors.New("Asset was already assigned.")
	}

	return nil, err
}

//@@ 자산 이체 함수
func (t *AssetManagementChaincode) transfer(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	if len(args) != 2 {
		return nil, errors.New("Incorrect number of arguments. Expecting 2")
	}

	asset := args[0]

	newOwner, err := base64.StdEncoding.DecodeString(args[1])
	if err != nil {
		fmt.Printf("Error decoding [%v] \n", err)
		return nil, errors.New("Failed decoding owner")
	}

	// Verify the identity of the caller
	// Only the owner can transfer one of his assets
	// 함수 호출자 검증. 오직 자산 소유자만이 자산을 이체할 권한이 있음.
	var columns []shim.Column
	col1 := shim.Column{Value: &shim.Column_String_{String_: asset}}
	columns = append(columns, col1)

	row, err := stub.GetRow("AssetsOwnership", columns)
	if err != nil {
		return nil, fmt.Errorf("Failed retrieving asset [%s]: [%s]", asset, err)
	}

	prvOwner := row.Columns[1].GetBytes()
	myLogger.Debugf("Previous owener of [%s] is [% x]", asset, prvOwner)
	if len(prvOwner) == 0 {
		return nil, fmt.Errorf("Invalid previous owner. Nil")
	}

	// Verify ownership
	//@@ 자산 권한을 검증
	callerAccount, err := stub.ReadCertAttribute("account")
	if err != nil {
		return nil, fmt.Errorf("Failed fetching caller account. Error was [%v]", err)
	}

	if bytes.Compare(prvOwner, callerAccount) != 0 {
		return nil, fmt.Errorf("Failed verifying caller ownership.")
	}
	// 자산을 이체 받을 자의 어카운트
	newOwnerAccount, err := attr.GetValueFrom("account", newOwner)
	if err != nil {
		return nil, fmt.Errorf("Failed fetching new owner account. Error was [%v]", err)
	}

	// At this point, the proof of ownership is valid, then register transfer
	//@@ 자산소유 권한이 유효한 것으로 검증 완료 시점. 자산 이체를 예약.
	err = stub.DeleteRow(
		"AssetsOwnership",
		[]shim.Column{shim.Column{Value: &shim.Column_String_{String_: asset}}},
	)
	if err != nil {
		return nil, errors.New("Failed deliting row.")
	}
	//@@ 자산을 이체 받을 자의 asset, account를 기록.(insert)
	_, err = stub.InsertRow(
		"AssetsOwnership",
		shim.Row{
			Columns: []*shim.Column{
				&shim.Column{Value: &shim.Column_String_{String_: asset}},
				&shim.Column{Value: &shim.Column_Bytes{Bytes: newOwnerAccount}},
			},
		})
	if err != nil {
		return nil, errors.New("Failed inserting row.")
	}

	return nil, nil
}

// Invoke runs callback representing the invocation of a chaincode
//@@ 체인코드의 invoke 펑션
func (t *AssetManagementChaincode) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {

	// Handle different functions
	// 이 체인코드는 자산 배정과 자산 이체 두 개의 펑션을 가지고 있음.
	if function == "assign" {
		// Assign ownership
		return t.assign(stub, args)
	} else if function == "transfer" {
		// Transfer ownership
		return t.transfer(stub, args)
	}

	return nil, errors.New("Received unknown function invocation")
}

// Query callback representing the query of a chaincode
// 쿼리 펑션은 체인코드의 조회 기능이 구현되어 있음.
func (t *AssetManagementChaincode) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	if function != "query" {
		return nil, errors.New("Invalid query function name. Expecting 'query' but found '" + function + "'")
	}

	var err error

	if len(args) != 1 {
		return nil, errors.New("Incorrect number of arguments. Expecting name of an asset to query")
	}

	// Who is the owner of the asset?
	//@@ 자산의 소유자는 누구인지에 대한 조회, 자산을 key로 받아서 소유자를 AssetOwnership에서 읽어옴.
	asset := args[0]

	fmt.Printf("ASSET: %v", string(asset))

	var columns []shim.Column
	col1 := shim.Column{Value: &shim.Column_String_{String_: asset}}
	columns = append(columns, col1)

	row, err := stub.GetRow("AssetsOwnership", columns)
	if err != nil {
		jsonResp := "{\"Error\":\"Failed retrieving asset " + asset + ". Error " + err.Error() + ". \"}"
		return nil, errors.New(jsonResp)
	}

	if len(row.Columns) == 0 {
		jsonResp := "{\"Error\":\"Failed retrieving owner for " + asset + ". \"}"
		return nil, errors.New(jsonResp)
	}

	jsonResp := "{\"Owner\":\"" + string(row.Columns[1].GetBytes()) + "\"}"
	fmt.Printf("Query Response:%s\n", jsonResp)

	return row.Columns[1].GetBytes(), nil
}

//@@ 실제 예시용 체인코드를 shim 컨테이너에서 실행시키는 메인 함수
func main() {
	err := shim.Start(new(AssetManagementChaincode))
	if err != nil {
		fmt.Printf("Error starting AssetManagementChaincode: %s", err)
	}
}
