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

// Package shim provides APIs for the chaincode to access its state
// variables, transaction context and call other chaincodes.
// @@ shim : 체인코드가 해당 코드의 상태 변수나 트랜잭션, 그리고 다른 체인코드에 접근 가능하도록 API를 제공하는 패키지
package shim

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/hyperledger/fabric/core/chaincode/shim/crypto/attr"
	"github.com/hyperledger/fabric/core/chaincode/shim/crypto/ecdsa"
	"github.com/hyperledger/fabric/core/comm"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

// Logger for the shim package.
// @@ shim 패키지에 대한 로깅 객체
var chaincodeLogger = logging.MustGetLogger("shim")

// Handler to shim that handles all control logic.
// @@ shim 핸들러 객체
var handler *Handler

// ChaincodeStub is an object passed to chaincode for shim side handling of
// APIs.
// @@ ChaincodeStub : API 핸들링을 위해 chaincode에 전달되는 객체
type ChaincodeStub struct {
	TxID            string
	securityContext *pb.ChaincodeSecurityContext
	chaincodeEvent  *pb.ChaincodeEvent
	args            [][]byte
}

// Peer address derived from command line or env var
// @@ 코맨드 라인이나 환경 변수에서 파생된 Peer address
var peerAddress string

// Start is the entry point for chaincodes bootstrap. It is not an API for
// chaincodes.
// @@ chaincode 부트스트랩 시작 포인트. 체인코드 API가 아님.
func Start(cc Chaincode) error {
	// If Start() is called, we assume this is a standalone chaincode and set
	// up formatted logging.
	// @@ Start가 호출되었음은 호출한 체인코드가 standalone인것으로 간주.
	format := logging.MustStringFormatter("%{time:15:04:05.000} [%{module}] %{level:.4s} : %{message}")
	backend := logging.NewLogBackend(os.Stderr, "", 0)
	backendFormatter := logging.NewBackendFormatter(backend, format)
	logging.SetBackend(backendFormatter).SetLevel(logging.Level(shimLoggingLevel), "shim")

	SetChaincodeLoggingLevel()

	flag.StringVar(&peerAddress, "peer.address", "", "peer address")

	flag.Parse()

	chaincodeLogger.Debugf("Peer address: %s", getPeerAddress())

	// Establish connection with validating peer
	// @@ vp와 새로운 연결 구성
	clientConn, err := newPeerClientConnection()
	if err != nil {
		chaincodeLogger.Errorf("Error trying to connect to local peer: %s", err)
		return fmt.Errorf("Error trying to connect to local peer: %s", err)
	}

	chaincodeLogger.Debugf("os.Args returns: %s", os.Args)

	chaincodeSupportClient := pb.NewChaincodeSupportClient(clientConn)

	// Establish stream with validating peer
	// @@ vp와 연결 성공(clientConn) 후, stream 구성
	stream, err := chaincodeSupportClient.Register(context.Background())
	if err != nil {
		return fmt.Errorf("Error chatting with leader at address=%s:  %s", getPeerAddress(), err)
	}

	chaincodename := viper.GetString("chaincode.id.name")
	if chaincodename == "" {
		return fmt.Errorf("Error chaincode id not provided")
	}
	// @@ KEEPALIVE로 스트림 유지
	err = chatWithPeer(chaincodename, stream, cc)

	return err
}

// IsEnabledForLogLevel checks to see if the chaincodeLogger is enabled for a specific logging level
// used primarily for testing
// @@ IsEnabledForLogLevel : 체인코드로거가 특정한 로깅 레벨로 셋업 될수 있는지 체크
func IsEnabledForLogLevel(logLevel string) bool {
	lvl, _ := logging.LogLevel(logLevel)
	return chaincodeLogger.IsEnabledFor(lvl)
}

// SetChaincodeLoggingLevel sets the chaincode logging level to the value
// of CORE_LOGGING_CHAINCODE set from core.yaml by chaincode_support.go
// @@ SetChaincodeLoggingLevel : 체인코드 로깅레벨을 core.yaml에 정의된 CORE_LOGGING_CHAINCODE값으로 셋
func SetChaincodeLoggingLevel() {
	viper.SetEnvPrefix("CORE")
	viper.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)

	chaincodeLogLevelString := viper.GetString("logging.chaincode")
	chaincodeLogLevel, err := LogLevel(chaincodeLogLevelString)

	if err == nil {
		SetLoggingLevel(chaincodeLogLevel)
	} else {
		chaincodeLogger.Infof("error with chaincode log level: %s level= %s\n", err, chaincodeLogLevelString)
	}
}

// StartInProc is an entry point for system chaincodes bootstrap. It is not an
// API for chaincodes.
// @@ StartInProc : system chaincode 부트스트랩을 위한 진입 포인트
//@@ chatWithPeer() 호출
//@@		peer 로 "REGISTER 요청" 송신 ( handler.ChatStream.Send() 실행 (Lock 처리) )
//@@		stream.Recv() 호출 : stream 에서 메시지 수신 ( + 에러처리 )
//@@		handler.nextState 에서 들어온 메시지 처리 : handler.FSM 의 State 를 전이(transition)
func StartInProc(env []string, args []string, cc Chaincode, recv <-chan *pb.ChaincodeMessage, send chan<- *pb.ChaincodeMessage) error {
	logging.SetLevel(logging.DEBUG, "chaincode")
	chaincodeLogger.Debugf("in proc %v", args)

	var chaincodename string
	for _, v := range env {
		if strings.Index(v, "CORE_CHAINCODE_ID_NAME=") == 0 {
			p := strings.SplitAfter(v, "CORE_CHAINCODE_ID_NAME=")
			chaincodename = p[1]
			break
		}
	}
	if chaincodename == "" {
		return fmt.Errorf("Error chaincode id not provided")
	}
	chaincodeLogger.Debugf("starting chat with peer using name=%s", chaincodename)
	stream := newInProcStream(recv, send)
	//@@ peer 로 "REGISTER 요청" 송신 ( handler.ChatStream.Send() 실행 (Lock 처리) )
	//@@ stream.Recv() 호출 : stream 에서 메시지 수신 ( + 에러처리 )
	//@@ handler.nextState 에서 들어온 메시지 처리 : handler.FSM 의 State 를 전이(transition)
	err := chatWithPeer(chaincodename, stream, cc)
	return err
}

// @@ peerAddress를 구함
func getPeerAddress() string {
	if peerAddress != "" {
		return peerAddress
	}

	if peerAddress = viper.GetString("peer.address"); peerAddress == "" {
		chaincodeLogger.Fatalf("peer.address not configured, can't connect to peer")
	}

	return peerAddress
}

// @@ 체인코드를 동작시킬 peer와의 코넥션을 생성
func newPeerClientConnection() (*grpc.ClientConn, error) {
	var peerAddress = getPeerAddress()
	if comm.TLSEnabled() {
		return comm.NewClientConnectionWithAddress(peerAddress, true, true, comm.InitTLSForPeer())
	}
	return comm.NewClientConnectionWithAddress(peerAddress, true, false, nil)
}


//@@ ChaincodeHandler 생성
//@@ peer 로 "REGISTER 요청" 송신 ( handler.ChatStream.Send() 실행 (Lock 처리) )
//@@ handler.handleMessage() 호출
//@@		수신된 Event 가 현재 State 에서 발생될 수 없는 것이면, 에러 처리
//@@		handler.FSM 의 State 를 전이(transition)
//@@		에러가 NoTransitionError 또는 CanceledError 이고,
//@@		embedded 에러 != nil 일 경우만 에러 리턴, 나머지는 모두 nil 리턴
//@@ stream.Recv() 호출 : stream 에서 메시지 수신 ( + 에러처리 )
//@@ handler.nextState 에서 들어온 메시지 처리 : handler.FSM 의 State 를 전이(transition)
//@@ waitc 채널 수신 대기 && handler 에러 리턴
func chatWithPeer(chaincodename string, stream PeerChaincodeStream, cc Chaincode) error {

	// Create the shim handler responsible for all control logic
	handler = newChaincodeHandler(stream, cc)

	defer stream.CloseSend()
	// Send the ChaincodeID during register.
	chaincodeID := &pb.ChaincodeID{Name: chaincodename}
	payload, err := proto.Marshal(chaincodeID)
	if err != nil {
		return fmt.Errorf("Error marshalling chaincodeID during chaincode registration: %s", err)
	}
	// Register on the stream
	chaincodeLogger.Debugf("Registering.. sending %s", pb.ChaincodeMessage_REGISTER)
	//@@ peer 로 "REGISTER 요청" 송신 ( handler.ChatStream.Send() 실행 (Lock 처리) )
	handler.serialSend(&pb.ChaincodeMessage{Type: pb.ChaincodeMessage_REGISTER, Payload: payload})
	waitc := make(chan struct{})
	go func() {
		defer close(waitc)
		msgAvail := make(chan *pb.ChaincodeMessage)
		var nsInfo *nextStateInfo
		var in *pb.ChaincodeMessage
		recv := true
		for {
			in = nil
			err = nil
			nsInfo = nil
			if recv {
				recv = false
				go func() {
					var in2 *pb.ChaincodeMessage
					in2, err = stream.Recv()
					msgAvail <- in2
				}()
			}
			select {
			case in = <-msgAvail:
				if err == io.EOF {
					chaincodeLogger.Debugf("Received EOF, ending chaincode stream, %s", err)
					return
				} else if err != nil {
					chaincodeLogger.Errorf("Received error from server: %s, ending chaincode stream", err)
					return
				} else if in == nil {
					err = fmt.Errorf("Received nil message, ending chaincode stream")
					chaincodeLogger.Debug("Received nil message, ending chaincode stream")
					return
				}
				chaincodeLogger.Debugf("[%s]Received message %s from shim", shorttxid(in.Txid), in.Type.String())
				recv = true
			case nsInfo = <-handler.nextState:
				in = nsInfo.msg
				if in == nil {
					panic("nil msg")
				}
				chaincodeLogger.Debugf("[%s]Move state message %s", shorttxid(in.Txid), in.Type.String())
			}

			// Call FSM.handleMessage()
			//@@ 수신된 Event 가 현재 State 에서 발생될 수 없는 것이면, 에러 처리
			//@@ handler.FSM 의 State 를 전이(transition)
			//@@ 에러가 NoTransitionError 또는 CanceledError 이고,
			//@@ embedded 에러 != nil 일 경우만 에러 리턴, 나머지는 모두 nil 리턴
			err = handler.handleMessage(in)
			if err != nil {
				err = fmt.Errorf("Error handling message: %s", err)
				return
			}

			//keepalive messages are PONGs to the fabric's PINGs
			//@@ KEEPALIVE 또는 응답 송신 처리
			if (nsInfo != nil && nsInfo.sendToCC) || (in.Type == pb.ChaincodeMessage_KEEPALIVE) {
				if in.Type == pb.ChaincodeMessage_KEEPALIVE {
					chaincodeLogger.Debug("Sending KEEPALIVE response")
				} else {
					chaincodeLogger.Debugf("[%s]send state message %s", shorttxid(in.Txid), in.Type.String())
				}
				if err = handler.serialSend(in); err != nil {
					err = fmt.Errorf("Error sending %s: %s", in.Type.String(), err)
					return
				}
			}
		}
	}()
	<-waitc
	return err
}

// -- init stub ---
// ChaincodeInvocation functionality
func (stub *ChaincodeStub) init(txid string, secContext *pb.ChaincodeSecurityContext) {
	stub.TxID = txid
	stub.securityContext = secContext
	stub.args = [][]byte{}
	newCI := pb.ChaincodeInput{}
	err := proto.Unmarshal(secContext.Payload, &newCI)
	if err == nil {
		stub.args = newCI.Args
	} else {
		panic("Arguments cannot be unmarshalled.")
	}
}

func (stub *ChaincodeStub) GetTxID() string {
	return stub.TxID
}

// --------- Security functions ----------
//CHAINCODE SEC INTERFACE FUNCS TOBE IMPLEMENTED BY ANGELO

// ------------- Call Chaincode functions ---------------

// InvokeChaincode locally calls the specified chaincode `Invoke` using the
// same transaction context; that is, chaincode calling chaincode doesn't
// create a new transaction message.
// @@ InvokeChaincode : 특정 체인코드의 Invoke를 호출,
// @@ 체인코드가 또 다른 체인코드를 호출할 때에는 새로운 트랜잭션 메세지를 생성하지 않음
func (stub *ChaincodeStub) InvokeChaincode(chaincodeName string, args [][]byte) ([]byte, error) {
	return handler.handleInvokeChaincode(chaincodeName, args, stub.TxID)
}

// QueryChaincode locally calls the specified chaincode `Query` using the
// same transaction context; that is, chaincode calling chaincode doesn't
// create a new transaction message.
// @@ QueryChaincode : 특정 체인코드의 Query를 호출,
// @@ 체인코드가 또 다른 체인코드를 호출할 때에는 새로운 트랜잭션 메세지를 생성하지 않음
func (stub *ChaincodeStub) QueryChaincode(chaincodeName string, args [][]byte) ([]byte, error) {
	return handler.handleQueryChaincode(chaincodeName, args, stub.TxID)
}

// --------- State functions ----------

// GetState returns the byte array value specified by the `key`.
// @@ GetState : 입력된 key에 해당하는 byte array value를 리턴
func (stub *ChaincodeStub) GetState(key string) ([]byte, error) {
	return handler.handleGetState(key, stub.TxID)
}

// PutState writes the specified `value` and `key` into the ledger.
// @@ Putstate : 특정 value와 key값을 ledger에 기록
func (stub *ChaincodeStub) PutState(key string, value []byte) error {
	return handler.handlePutState(key, value, stub.TxID)
}

// DelState removes the specified `key` and its value from the ledger.
// @@ Delstate : 특정 key 입력시, 대응되는 value와 함께 ledger에서 삭제
func (stub *ChaincodeStub) DelState(key string) error {
	return handler.handleDelState(key, stub.TxID)
}

//ReadCertAttribute is used to read an specific attribute from the transaction certificate,
//*attributeName* is passed as input parameter to this function.
// Example:
//  attrValue,error:=stub.ReadCertAttribute("position")
// @@ ReadCertAttribute : 특정 attribute를 Tcert에서 읽어내는데 이용됨. attributeName이 이 함수의 입력 파라미터.
func (stub *ChaincodeStub) ReadCertAttribute(attributeName string) ([]byte, error) {
	attributesHandler, err := attr.NewAttributesHandlerImpl(stub)
	if err != nil {
		return nil, err
	}
	return attributesHandler.GetValue(attributeName)
}

//VerifyAttribute is used to verify if the transaction certificate has an attribute with name *attributeName* and value *attributeValue* which are the input parameters received by this function.
//Example:
//    containsAttr, error := stub.VerifyAttribute("position", "Software Engineer")
// @@ VerifyAttribute : Tcert가 입력된 attributeName에 해당하는 attribute를 가졌는지 검증.
func (stub *ChaincodeStub) VerifyAttribute(attributeName string, attributeValue []byte) (bool, error) {
	attributesHandler, err := attr.NewAttributesHandlerImpl(stub)
	if err != nil {
		return false, err
	}
	return attributesHandler.VerifyAttribute(attributeName, attributeValue)
}

//VerifyAttributes does the same as VerifyAttribute but it checks for a list of attributes and their respective values instead of a single attribute/value pair
// Example:
//    containsAttrs, error:= stub.VerifyAttributes(&attr.Attribute{"position",  "Software Engineer"}, &attr.Attribute{"company", "ACompany"})
// @@ VerifyAttributes : VerifyAttribute와 동일한 기능 수행. 다만, 복수개의 attribute를 다룸.
func (stub *ChaincodeStub) VerifyAttributes(attrs ...*attr.Attribute) (bool, error) {
	attributesHandler, err := attr.NewAttributesHandlerImpl(stub)
	if err != nil {
		return false, err
	}
	return attributesHandler.VerifyAttributes(attrs...)
}

// StateRangeQueryIterator allows a chaincode to iterate over a range of
// key/value pairs in the state.
// @@ StateRangeQueryIterator : 체인코드가 state의 특정 범위안에 있는 key/value 쌍을 iterate하도록 허용
type StateRangeQueryIterator struct {
	handler    *Handler
	uuid       string
	response   *pb.RangeQueryStateResponse
	currentLoc int
}

// RangeQueryState function can be invoked by a chaincode to query of a range
// of keys in the state. Assuming the startKey and endKey are in lexical order,
// an iterator will be returned that can be used to iterate over all keys
// between the startKey and endKey, inclusive. The order in which keys are
// returned by the iterator is random.
// @@ RangeQueryState : 체인코드가 state내 특정 범위의 key에 대한 query를 행할 수 있도록 함.
// @@ lexical ordering된 시작과 종료 키값 내의 모든 key를 iterate하고 iterator가 반환되는데 이 때, 리턴되는 key의 순서는 random이다.
func (stub *ChaincodeStub) RangeQueryState(startKey, endKey string) (StateRangeQueryIteratorInterface, error) {
	response, err := handler.handleRangeQueryState(startKey, endKey, stub.TxID)
	if err != nil {
		return nil, err
	}
	return &StateRangeQueryIterator{handler, stub.TxID, response, 0}, nil
}

// HasNext returns true if the range query iterator contains additional keys
// and values.
// @@ HasNext : range query iterator가 추가적인 key와 value값을 가졌는지 여부를 체크
func (iter *StateRangeQueryIterator) HasNext() bool {
	if iter.currentLoc < len(iter.response.KeysAndValues) || iter.response.HasMore {
		return true
	}
	return false
}

// Next returns the next key and value in the range query iterator.
// @@ Next : range query iterator의 Next key와 value를 리턴.
func (iter *StateRangeQueryIterator) Next() (string, []byte, error) {
	if iter.currentLoc < len(iter.response.KeysAndValues) {
		keyValue := iter.response.KeysAndValues[iter.currentLoc]
		iter.currentLoc++
		return keyValue.Key, keyValue.Value, nil
	} else if !iter.response.HasMore {
		return "", nil, errors.New("No such key")
	} else {
		response, err := iter.handler.handleRangeQueryStateNext(iter.response.ID, iter.uuid)

		if err != nil {
			return "", nil, err
		}

		iter.currentLoc = 0
		iter.response = response
		keyValue := iter.response.KeysAndValues[iter.currentLoc]
		iter.currentLoc++
		return keyValue.Key, keyValue.Value, nil

	}
}

// Close closes the range query iterator. This should be called when done
// reading from the iterator to free up resources.
// @@ Close : range query iterator를 닫음. iterator로 인해 점유된 자원을 free시킴. iterator사용 후, 꼭 호출해야 함
func (iter *StateRangeQueryIterator) Close() error {
	_, err := iter.handler.handleRangeQueryStateClose(iter.response.ID, iter.uuid)
	return err
}

func (stub *ChaincodeStub) GetArgs() [][]byte {
	return stub.args
}

func (stub *ChaincodeStub) GetStringArgs() []string {
	args := stub.GetArgs()
	strargs := make([]string, 0, len(args))
	for _, barg := range args {
		strargs = append(strargs, string(barg))
	}
	return strargs
}

// TABLE FUNCTIONALITY
// TODO More comments here with documentation

// Table Errors
var (
	// ErrTableNotFound if the specified table cannot be found
	ErrTableNotFound = errors.New("chaincode: Table not found")
)

// CreateTable creates a new table given the table name and column definitions
// @@ CreateTable : 주어진 테이블명과 column definition에 따라 새로운 테이블을 생성
func (stub *ChaincodeStub) CreateTable(name string, columnDefinitions []*ColumnDefinition) error {

	_, err := stub.getTable(name)
	if err == nil {
		return fmt.Errorf("CreateTable operation failed. Table %s already exists.", name)
	}
	if err != ErrTableNotFound {
		return fmt.Errorf("CreateTable operation failed. %s", err)
	}

	if columnDefinitions == nil || len(columnDefinitions) == 0 {
		return errors.New("Invalid column definitions. Tables must contain at least one column.")
	}

	hasKey := false
	nameMap := make(map[string]bool)
	for i, definition := range columnDefinitions {

		// Check name
		if definition == nil {
			return fmt.Errorf("Column definition %d is invalid. Definition must not be nil.", i)
		}
		if len(definition.Name) == 0 {
			return fmt.Errorf("Column definition %d is invalid. Name must be 1 or more characters.", i)
		}
		if _, exists := nameMap[definition.Name]; exists {
			return fmt.Errorf("Invalid table. Table contains duplicate column name '%s'.", definition.Name)
		}
		nameMap[definition.Name] = true

		// Check type
		switch definition.Type {
		case ColumnDefinition_STRING:
		case ColumnDefinition_INT32:
		case ColumnDefinition_INT64:
		case ColumnDefinition_UINT32:
		case ColumnDefinition_UINT64:
		case ColumnDefinition_BYTES:
		case ColumnDefinition_BOOL:
		default:
			return fmt.Errorf("Column definition %s does not have a valid type.", definition.Name)
		}

		if definition.Key {
			hasKey = true
		}
	}

	if !hasKey {
		return errors.New("Inavlid table. One or more columns must be a key.")
	}

	table := &Table{name, columnDefinitions}
	tableBytes, err := proto.Marshal(table)
	if err != nil {
		return fmt.Errorf("Error marshalling table: %s", err)
	}
	tableNameKey, err := getTableNameKey(name)
	if err != nil {
		return fmt.Errorf("Error creating table key: %s", err)
	}
	err = stub.PutState(tableNameKey, tableBytes)
	if err != nil {
		return fmt.Errorf("Error inserting table in state: %s", err)
	}
	return nil
}

// GetTable returns the table for the specified table name or ErrTableNotFound
// if the table does not exist.
// @@ GetTable : 특정 테이블명에 해당하는 테이블을 리턴. 존재하지 않을 경우, ErrTableNotFound가 리턴.
func (stub *ChaincodeStub) GetTable(tableName string) (*Table, error) {
	return stub.getTable(tableName)
}

// DeleteTable deletes an entire table and all associated rows.
// @@ DeleteTable : 전체 테이블과 관련된 rows를 삭제
func (stub *ChaincodeStub) DeleteTable(tableName string) error {
	tableNameKey, err := getTableNameKey(tableName)
	if err != nil {
		return err
	}

	// Delete rows
	iter, err := stub.RangeQueryState(tableNameKey+"1", tableNameKey+":")
	if err != nil {
		return fmt.Errorf("Error deleting table: %s", err)
	}
	defer iter.Close()
	for iter.HasNext() {
		key, _, err := iter.Next()
		if err != nil {
			return fmt.Errorf("Error deleting table: %s", err)
		}
		err = stub.DelState(key)
		if err != nil {
			return fmt.Errorf("Error deleting table: %s", err)
		}
	}

	return stub.DelState(tableNameKey)
}

// InsertRow inserts a new row into the specified table.
// Returns -
// true and no error if the row is successfully inserted.
// false and no error if a row already exists for the given key.
// false and a TableNotFoundError if the specified table name does not exist.
// false and an error if there is an unexpected error condition.
// @@ InsertRow : 새로운 row를 특정 테이블에 insert.
// @@ 성공시(true, no error),
// @@ 중복시(false, no error), 해당테이블이 존재하지 않을 경우(false, TableNotFoundError), 기타 예상치 못한 에러(false, error)
func (stub *ChaincodeStub) InsertRow(tableName string, row Row) (bool, error) {
	return stub.insertRowInternal(tableName, row, false)
}

// ReplaceRow updates the row in the specified table.
// Returns -
// true and no error if the row is successfully updated.
// false and no error if a row does not exist the given key.
// flase and a TableNotFoundError if the specified table name does not exist.
// false and an error if there is an unexpected error condition.
// @@ ReplaceRow : 특정 테이블의 row를 update.
// @@ 성공시(true, no error),
// @@ 입력key에 해당하는 row가 없을시(false, no error), 해당테이블이 존재하지 않을 경우(false, TableNotFoundError), 기타 예상치 못한 에러(false, error)
func (stub *ChaincodeStub) ReplaceRow(tableName string, row Row) (bool, error) {
	return stub.insertRowInternal(tableName, row, true)
}

// GetRow fetches a row from the specified table for the given key.
// @@ GetRow : 특정 테이블에서 key값에 해당하는 row를 fetch
func (stub *ChaincodeStub) GetRow(tableName string, key []Column) (Row, error) {

	var row Row

	keyString, err := buildKeyString(tableName, key)
	if err != nil {
		return row, err
	}

	rowBytes, err := stub.GetState(keyString)
	if err != nil {
		return row, fmt.Errorf("Error fetching row from DB: %s", err)
	}

	err = proto.Unmarshal(rowBytes, &row)
	if err != nil {
		return row, fmt.Errorf("Error unmarshalling row: %s", err)
	}

	return row, nil

}

// GetRows returns multiple rows based on a partial key. For example, given table
// | A | B | C | D |
// where A, C and D are keys, GetRows can be called with [A, C] to return
// all rows that have A, C and any value for D as their key. GetRows could
// also be called with A only to return all rows that have A and any value
// for C and D as their key.
// @@ GetRows : key값에 해당하는 복수개의 rows를 리턴.
// @@ 예를 들어, A,B,C,D라는 4개의 컬럼을 둔 테이블에서 A,C,D가 key로 셋팅되어 있다면, (A,C) 또는 (A)로 Getrows를 호출가능.
func (stub *ChaincodeStub) GetRows(tableName string, key []Column) (<-chan Row, error) {

	keyString, err := buildKeyString(tableName, key)
	if err != nil {
		return nil, err
	}

	table, err := stub.getTable(tableName)
	if err != nil {
		return nil, err
	}

	// Need to check for special case where table has a single column
	if len(table.GetColumnDefinitions()) < 2 && len(key) > 0 {

		row, err := stub.GetRow(tableName, key)
		if err != nil {
			return nil, err
		}
		rows := make(chan Row)
		go func() {
			rows <- row
			close(rows)
		}()
		return rows, nil
	}

	iter, err := stub.RangeQueryState(keyString+"1", keyString+":")
	if err != nil {
		return nil, fmt.Errorf("Error fetching rows: %s", err)
	}
	defer iter.Close()

	rows := make(chan Row)

	go func() {
		for iter.HasNext() {
			_, rowBytes, err := iter.Next()
			if err != nil {
				close(rows)
			}

			var row Row
			err = proto.Unmarshal(rowBytes, &row)
			if err != nil {
				close(rows)
			}

			rows <- row

		}
		close(rows)
	}()

	return rows, nil

}

// DeleteRow deletes the row for the given key from the specified table.
// @@ DeleteRow : 특정 테이블의 주어진 key에 해당하는 row를 삭제.
func (stub *ChaincodeStub) DeleteRow(tableName string, key []Column) error {

	keyString, err := buildKeyString(tableName, key)
	if err != nil {
		return err
	}

	err = stub.DelState(keyString)
	if err != nil {
		return fmt.Errorf("DeleteRow operation error. Error deleting row: %s", err)
	}

	return nil
}

// VerifySignature verifies the transaction signature and returns `true` if
// correct and `false` otherwise
// @@ VerifySignature : 트랜잭션 서명을 검증하고 만약 정상이라면 true를 리턴.
func (stub *ChaincodeStub) VerifySignature(certificate, signature, message []byte) (bool, error) {
	// Instantiate a new SignatureVerifier
	sv := ecdsa.NewX509ECDSASignatureVerifier()

	// Verify the signature
	return sv.Verify(certificate, signature, message)
}

// GetCallerCertificate returns caller certificate
// @@ GetCallerCertificate : 호출자의 cert를 리턴 -- /protos/chaincode.proto에 정의된 message ChaincodeSecurityContext 타입의 속성 중 하나
func (stub *ChaincodeStub) GetCallerCertificate() ([]byte, error) {
	return stub.securityContext.CallerCert, nil
}

// GetCallerMetadata returns caller metadata
// @@ GetCallerMetadata : 호출자의 metadata를 리턴 -- /protos/chaincode.proto에 정의된 message ChaincodeSecurityContext 타입의 속성 중 하나
func (stub *ChaincodeStub) GetCallerMetadata() ([]byte, error) {
	return stub.securityContext.Metadata, nil
}

// GetBinding returns the transaction binding
// @@ GetBinding : 트랜잭션 바인딩을 리턴 -- /protos/chaincode.proto에 정의된 message ChaincodeSecurityContext 타입의 속성 중 하나
func (stub *ChaincodeStub) GetBinding() ([]byte, error) {
	return stub.securityContext.Binding, nil
}

// GetPayload returns transaction payload, which is a `ChaincodeSpec` defined
// in fabric/protos/chaincode.proto
// @@ GetPayload : fabric/protos/chaincode.proto에 체인코드 스펙(ChaincodeSpec)으로 정의된 트랜잭션 payload를 리턴.
func (stub *ChaincodeStub) GetPayload() ([]byte, error) {
	return stub.securityContext.Payload, nil
}

// GetTxTimestamp returns transaction created timestamp, which is currently
// taken from the peer receiving the transaction. Note that this timestamp
// may not be the same with the other peers' time.
// @@ GetTxTimestamp : 트랜잭션의 생성 시점의 타임스탬프를 리턴. 이 시각은 피어가 트랜잭션을 수신시 필요.
// @@ 이 시각은 다른 피어들의 시각과 다를 수 있음.
func (stub *ChaincodeStub) GetTxTimestamp() (*timestamp.Timestamp, error) {
	return stub.securityContext.TxTimestamp, nil
}

func (stub *ChaincodeStub) getTable(tableName string) (*Table, error) {

	tableName, err := getTableNameKey(tableName)
	if err != nil {
		return nil, err
	}

	tableBytes, err := stub.GetState(tableName)
	if tableBytes == nil {
		return nil, ErrTableNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("Error fetching table: %s", err)
	}
	table := &Table{}
	err = proto.Unmarshal(tableBytes, table)
	if err != nil {
		return nil, fmt.Errorf("Error unmarshalling table: %s", err)
	}

	return table, nil
}

func validateTableName(name string) error {
	if len(name) == 0 {
		return errors.New("Inavlid table name. Table name must be 1 or more characters.")
	}

	return nil
}

func getTableNameKey(name string) (string, error) {
	err := validateTableName(name)
	if err != nil {
		return "", err
	}

	return strconv.Itoa(len(name)) + name, nil
}

func buildKeyString(tableName string, keys []Column) (string, error) {

	var keyBuffer bytes.Buffer

	tableNameKey, err := getTableNameKey(tableName)
	if err != nil {
		return "", err
	}

	keyBuffer.WriteString(tableNameKey)

	for _, key := range keys {

		var keyString string
		switch key.Value.(type) {
		case *Column_String_:
			keyString = key.GetString_()
		case *Column_Int32:
			// b := make([]byte, 4)
			// binary.LittleEndian.PutUint32(b, uint32(key.GetInt32()))
			// keyBuffer.Write(b)
			keyString = strconv.FormatInt(int64(key.GetInt32()), 10)
		case *Column_Int64:
			keyString = strconv.FormatInt(key.GetInt64(), 10)
		case *Column_Uint32:
			keyString = strconv.FormatUint(uint64(key.GetUint32()), 10)
		case *Column_Uint64:
			keyString = strconv.FormatUint(key.GetUint64(), 10)
		case *Column_Bytes:
			keyString = string(key.GetBytes())
		case *Column_Bool:
			keyString = strconv.FormatBool(key.GetBool())
		}

		keyBuffer.WriteString(strconv.Itoa(len(keyString)))
		keyBuffer.WriteString(keyString)
	}

	return keyBuffer.String(), nil
}

func getKeyAndVerifyRow(table Table, row Row) ([]Column, error) {

	var keys []Column

	if row.Columns == nil || len(row.Columns) != len(table.ColumnDefinitions) {
		return keys, fmt.Errorf("Table '%s' defines %d columns, but row has %d columns.",
			table.Name, len(table.ColumnDefinitions), len(row.Columns))
	}

	for i, column := range row.Columns {

		// Check types
		var expectedType bool
		switch column.Value.(type) {
		case *Column_String_:
			expectedType = table.ColumnDefinitions[i].Type == ColumnDefinition_STRING
		case *Column_Int32:
			expectedType = table.ColumnDefinitions[i].Type == ColumnDefinition_INT32
		case *Column_Int64:
			expectedType = table.ColumnDefinitions[i].Type == ColumnDefinition_INT64
		case *Column_Uint32:
			expectedType = table.ColumnDefinitions[i].Type == ColumnDefinition_UINT32
		case *Column_Uint64:
			expectedType = table.ColumnDefinitions[i].Type == ColumnDefinition_UINT64
		case *Column_Bytes:
			expectedType = table.ColumnDefinitions[i].Type == ColumnDefinition_BYTES
		case *Column_Bool:
			expectedType = table.ColumnDefinitions[i].Type == ColumnDefinition_BOOL
		default:
			expectedType = false
		}
		if !expectedType {
			return keys, fmt.Errorf("The type for table '%s', column '%s' is '%s', but the column in the row does not match.",
				table.Name, table.ColumnDefinitions[i].Name, table.ColumnDefinitions[i].Type)
		}

		if table.ColumnDefinitions[i].Key {
			keys = append(keys, *column)
		}

	}

	return keys, nil
}

func (stub *ChaincodeStub) isRowPresent(tableName string, key []Column) (bool, error) {
	keyString, err := buildKeyString(tableName, key)
	if err != nil {
		return false, err
	}
	rowBytes, err := stub.GetState(keyString)
	if err != nil {
		return false, fmt.Errorf("Error fetching row for key %s: %s", keyString, err)
	}
	if rowBytes != nil {
		return true, nil
	}
	return false, nil

}

// insertRowInternal inserts a new row into the specified table.
// Returns -
// true and no error if the row is successfully inserted.
// false and no error if a row already exists for the given key.
// false and a TableNotFoundError if the specified table name does not exist.
// false and an error if there is an unexpected error condition.
// @@ insertRowInternal : 새로운 row를 특정 테이블에 insert
// @@ 성공시(true, no error),
// @@ 중복시(false, no error), 해당테이블이 존재하지 않을 경우(false, TableNotFoundError), 기타 예상치 못한 에러(false, error)
// @@ func InsertRow와 func ReplaceRow가 insertRowInternal을 호출
func (stub *ChaincodeStub) insertRowInternal(tableName string, row Row, update bool) (bool, error) {

	table, err := stub.getTable(tableName)
	if err != nil {
		return false, err
	}

	key, err := getKeyAndVerifyRow(*table, row)
	if err != nil {
		return false, err
	}

	present, err := stub.isRowPresent(tableName, key)
	if err != nil {
		return false, err
	}
	if (present && !update) || (!present && update) {
		return false, nil
	}

	rowBytes, err := proto.Marshal(&row)
	if err != nil {
		return false, fmt.Errorf("Error marshalling row: %s", err)
	}

	keyString, err := buildKeyString(tableName, key)
	if err != nil {
		return false, err
	}
	err = stub.PutState(keyString, rowBytes)
	if err != nil {
		return false, fmt.Errorf("Error inserting row in table %s: %s", tableName, err)
	}

	return true, nil
}

// ------------- ChaincodeEvent API ----------------------

// SetEvent saves the event to be sent when a transaction is made part of a block
// @@ SetEvent : 트랜잭션이 만들어질 때, 송신되어야할 이벤트를 저장
func (stub *ChaincodeStub) SetEvent(name string, payload []byte) error {
	stub.chaincodeEvent = &pb.ChaincodeEvent{EventName: name, Payload: payload}
	return nil
}

// ------------- Logging Control and Chaincode Loggers ---------------

// As independent programs, Go language chaincodes can use any logging
// methodology they choose, from simple fmt.Printf() to os.Stdout, to
// decorated logs created by the author's favorite logging package. The
// chaincode "shim" interface, however, is defined by the Hyperledger fabric
// and implements its own logging methodology. This methodology currently
// includes severity-based logging control and a standard way of decorating
// the logs.
//
// The facilities defined here allow a Go language chaincode to control the
// logging level of its shim, and to create its own logs formatted
// consistently with, and temporally interleaved with the shim logs without
// any knowledge of the underlying implementation of the shim, and without any
// other package requirements. The lack of package requirements is especially
// important because even if the chaincode happened to explicitly use the same
// logging package as the shim, unless the chaincode is physically included as
// part of the hyperledger fabric source code tree it could actually end up
// using a distinct binary instance of the logging package, with different
// formats and severity levels than the binary package used by the shim.
//
// Another approach that might have been taken, and could potentially be taken
// in the future, would be for the chaincode to supply a logging object for
// the shim to use, rather than the other way around as implemented
// here. There would be some complexities associated with that approach, so
// for the moment we have chosen the simpler implementation below. The shim
// provides one or more abstract logging objects for the chaincode to use via
// the NewLogger() API, and allows the chaincode to control the severity level
// of shim logs using the SetLoggingLevel() API.

// @@ shim은 NewLogger() API를 통해 추상화된 로깅 객체를 체인코드에 제공.
// @@ 체인코드가 shim log의 레벨을 컨트롤할 수 있도록 SetLoggingLevel() API를 제공.

// LoggingLevel is an enumerated type of severity levels that control
// chaincode logging.
// @@ LoggingLevel : enumeration type의 체인코드 로깅 레벨
type LoggingLevel logging.Level

// These constants comprise the LoggingLevel enumeration
const (
	LogDebug    = LoggingLevel(logging.DEBUG)
	LogInfo     = LoggingLevel(logging.INFO)
	LogNotice   = LoggingLevel(logging.NOTICE)
	LogWarning  = LoggingLevel(logging.WARNING)
	LogError    = LoggingLevel(logging.ERROR)
	LogCritical = LoggingLevel(logging.CRITICAL)
)

var shimLoggingLevel = LogDebug // Necessary for correct initialization; See Start()

// SetLoggingLevel allows a Go language chaincode to set the logging level of
// its shim.
// @@ SetLoggingLevel : go언어 체인코드가 shim의 로깅 레벨을 정의할 수 있도록 함
func SetLoggingLevel(level LoggingLevel) {
	shimLoggingLevel = level
	logging.SetLevel(logging.Level(level), "shim")
}

// LogLevel converts a case-insensitive string chosen from CRITICAL, ERROR,
// WARNING, NOTICE, INFO or DEBUG into an element of the LoggingLevel
// type. In the event of errors the level returned is LogError.
// @@ LogLevel : 대소문자를 구분하는 로깅 문자열을 LoggingLevel로 정의된 6개의 엘리먼트 타입으로 변환
func LogLevel(levelString string) (LoggingLevel, error) {
	l, err := logging.LogLevel(levelString)
	level := LoggingLevel(l)
	if err != nil {
		level = LogError
	}
	return level, err
}

// ------------- Chaincode Loggers ---------------

// ChaincodeLogger is an abstraction of a logging object for use by
// chaincodes. These objects are created by the NewLogger API.
// @@ ChaincodeLogger : 체인코드가 사용하는 로깅 객체. 이 객체는 NewLogger API로 생성됨.
type ChaincodeLogger struct {
	logger *logging.Logger
}

// NewLogger allows a Go language chaincode to create one or more logging
// objects whose logs will be formatted consistently with, and temporally
// interleaved with the logs created by the shim interface. The logs created
// by this object can be distinguished from shim logs by the name provided,
// which will appear in the logs.
// @@ NewLogger : go언어 체인코드가 하나 이상의 로깅 객체를 생성하도록 허용. 이 로깅 객체의 로그는 정형화되어 있으며, shim interface에 의해
// @@ 생성된 로그가 일시적으로 사이에 껴 있기도 하다. 이 로깅 객체로 인해 생성된 로그는 shim log와 이름으로 구분될 수 있다.
func NewLogger(name string) *ChaincodeLogger {
	return &ChaincodeLogger{logging.MustGetLogger(name)}
}

// SetLevel sets the logging level for a chaincode logger. Note that currently
// the levels are actually controlled by the name given when the logger is
// created, so loggers should be given unique names other than "shim".
// @@ SetLevel : 체인코드 로거의 로깅 레벨을 정의. 이 레벨은 로거의 생성 시점에 붙여진 이름에 의해서 컨트롤되므로
// @@ 로거는 shim이 아닌 고유한 이름을 부여 받아야 한다.
func (c *ChaincodeLogger) SetLevel(level LoggingLevel) {
	logging.SetLevel(logging.Level(level), c.logger.Module)
}

// IsEnabledFor returns true if the logger is enabled to creates logs at the
// given logging level.
// @@ IsEnabledFor : 로거가 주어진 로깅 레벨에 맞춰 로그를 생성 가능하다면 참을 리턴.
func (c *ChaincodeLogger) IsEnabledFor(level LoggingLevel) bool {
	return c.logger.IsEnabledFor(logging.Level(level))
}

// Debug logs will only appear if the ChaincodeLogger LoggingLevel is set to
// LogDebug.
// @@ Debug : ChaincodeLogger의 로깅 레벨이 LogDebug로 설정되어 있을 때 debug log가 나타난다.
func (c *ChaincodeLogger) Debug(args ...interface{}) {
	c.logger.Debug(args...)
}

// Info logs will appear if the ChaincodeLogger LoggingLevel is set to
// LogInfo or LogDebug.
func (c *ChaincodeLogger) Info(args ...interface{}) {
	c.logger.Info(args...)
}

// Notice logs will appear if the ChaincodeLogger LoggingLevel is set to
// LogNotice, LogInfo or LogDebug.
func (c *ChaincodeLogger) Notice(args ...interface{}) {
	c.logger.Notice(args...)
}

// Warning logs will appear if the ChaincodeLogger LoggingLevel is set to
// LogWarning, LogNotice, LogInfo or LogDebug.
func (c *ChaincodeLogger) Warning(args ...interface{}) {
	c.logger.Warning(args...)
}

// Error logs will appear if the ChaincodeLogger LoggingLevel is set to
// LogError, LogWarning, LogNotice, LogInfo or LogDebug.
func (c *ChaincodeLogger) Error(args ...interface{}) {
	c.logger.Error(args...)
}

// Critical logs always appear; They can not be disabled.
func (c *ChaincodeLogger) Critical(args ...interface{}) {
	c.logger.Critical(args...)
}

// Debugf logs will only appear if the ChaincodeLogger LoggingLevel is set to
// LogDebug.
func (c *ChaincodeLogger) Debugf(format string, args ...interface{}) {
	c.logger.Debugf(format, args...)
}

// Infof logs will appear if the ChaincodeLogger LoggingLevel is set to
// LogInfo or LogDebug.
func (c *ChaincodeLogger) Infof(format string, args ...interface{}) {
	c.logger.Infof(format, args...)
}

// Noticef logs will appear if the ChaincodeLogger LoggingLevel is set to
// LogNotice, LogInfo or LogDebug.
func (c *ChaincodeLogger) Noticef(format string, args ...interface{}) {
	c.logger.Noticef(format, args...)
}

// Warningf logs will appear if the ChaincodeLogger LoggingLevel is set to
// LogWarning, LogNotice, LogInfo or LogDebug.
func (c *ChaincodeLogger) Warningf(format string, args ...interface{}) {
	c.logger.Warningf(format, args...)
}

// Errorf logs will appear if the ChaincodeLogger LoggingLevel is set to
// LogError, LogWarning, LogNotice, LogInfo or LogDebug.
func (c *ChaincodeLogger) Errorf(format string, args ...interface{}) {
	c.logger.Errorf(format, args...)
}

// Criticalf logs always appear; They can not be disabled.
// @@ Criticalf : critical 레벨의 로그는 언제나 나타난다. 이 레벨의 로그는 disable될 수 없다.
func (c *ChaincodeLogger) Criticalf(format string, args ...interface{}) {
	c.logger.Criticalf(format, args...)
}
