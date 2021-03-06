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

package shim

import (
	"errors"
	"fmt"
	"sync"

	"github.com/golang/protobuf/proto"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/looplab/fsm"
)

// PeerChaincodeStream interface for stream between Peer and chaincode instance.
// @@ PeerChaincodeStream : 피어와 체인코드 인스턴스간의 stream I/F
type PeerChaincodeStream interface {
	Send(*pb.ChaincodeMessage) error
	Recv() (*pb.ChaincodeMessage, error)
	CloseSend() error
}

type nextStateInfo struct {
	msg      *pb.ChaincodeMessage
	sendToCC bool
}

func (handler *Handler) triggerNextState(msg *pb.ChaincodeMessage, send bool) {
	handler.nextState <- &nextStateInfo{msg, send}
}

// Handler handler implementation for shim side of chaincode.
// @@ Handler : shim의 체인코드 핸들러.
type Handler struct {
	sync.RWMutex
	//shim to peer grpc serializer. User only in serialSend
	// @@ peer쪽에서 rpc 요청에 대한 직렬화
	serialLock sync.Mutex
	To         string
	ChatStream PeerChaincodeStream
	FSM        *fsm.FSM
	cc         Chaincode
	// Multiple queries (and one transaction) with different txids can be executing in parallel for this chaincode
	// responseChannel is the channel on which responses are communicated by the shim to the chaincodeStub.
	// 체인코드의 서로 다른 txid에 대한 복수의 쿼리는 병렬로 진행 가능. responseChannel은 shim이 chaincodStub와 통신하며 응답하는 채널.
	responseChannel map[string]chan pb.ChaincodeMessage
	// Track which TXIDs are transactions and which are queries, to decide whether get/put state and invoke chaincode are allowed.
	isTransaction map[string]bool
	nextState     chan *nextStateInfo
}

func shorttxid(txid string) string {
	if len(txid) < 8 {
		return txid
	}
	return txid[0:8]
}

//@@ handler.ChatStream.Send() 실행 (Lock 처리)
func (handler *Handler) serialSend(msg *pb.ChaincodeMessage) error {
	handler.serialLock.Lock()
	defer handler.serialLock.Unlock()
	if err := handler.ChatStream.Send(msg); err != nil {
		chaincodeLogger.Errorf("[%s]Error sending %s: %s", shorttxid(msg.Txid), msg.Type.String(), err)
		return fmt.Errorf("Error sending %s: %s", msg.Type.String(), err)
	}
	return nil
}

// @@ 채널 생성
func (handler *Handler) createChannel(txid string) (chan pb.ChaincodeMessage, error) {
	handler.Lock()
	defer handler.Unlock()
	if handler.responseChannel == nil {
		return nil, fmt.Errorf("[%s]Cannot create response channel", shorttxid(txid))
	}
	if handler.responseChannel[txid] != nil {
		return nil, fmt.Errorf("[%s]Channel exists", shorttxid(txid))
	}
	c := make(chan pb.ChaincodeMessage)
	handler.responseChannel[txid] = c
	return c, nil
}

// @@ 송신
func (handler *Handler) sendChannel(msg *pb.ChaincodeMessage) error {
	handler.Lock()
	defer handler.Unlock()
	if handler.responseChannel == nil {
		return fmt.Errorf("[%s]Cannot send message response channel", shorttxid(msg.Txid))
	}
	if handler.responseChannel[msg.Txid] == nil {
		return fmt.Errorf("[%s]sendChannel does not exist", shorttxid(msg.Txid))
	}

	chaincodeLogger.Debugf("[%s]before send", shorttxid(msg.Txid))
	handler.responseChannel[msg.Txid] <- *msg
	chaincodeLogger.Debugf("[%s]after send", shorttxid(msg.Txid))

	return nil
}

// @@ 수신
func (handler *Handler) receiveChannel(c chan pb.ChaincodeMessage) (pb.ChaincodeMessage, bool) {
	msg, val := <-c
	return msg, val
}

// @@ 채널 삭제
func (handler *Handler) deleteChannel(txid string) {
	handler.Lock()
	defer handler.Unlock()
	if handler.responseChannel != nil {
		delete(handler.responseChannel, txid)
	}
}

// markIsTransaction marks a TXID as a transaction or a query; true = transaction, false = query
// @@ markIsTransaction : TXID가 트랜잭션인지 query인지를 구분하여 마킹. true이면 트랜잭션, false이면 query
func (handler *Handler) markIsTransaction(txid string, isTrans bool) bool {
	if handler.isTransaction == nil {
		return false
	}
	handler.Lock()
	defer handler.Unlock()
	handler.isTransaction[txid] = isTrans
	return true
}

// @@ TXID가 트랜잭션일 경우, 트랜잭션 삭제
func (handler *Handler) deleteIsTransaction(txid string) {
	handler.Lock()
	if handler.isTransaction != nil {
		delete(handler.isTransaction, txid)
	}
	handler.Unlock()
}

// NewChaincodeHandler returns a new instance of the shim side handler.
// @@ NewChaincodeHandler : 새로운 핸들러 인스턴스를 리턴.
func newChaincodeHandler(peerChatStream PeerChaincodeStream, chaincode Chaincode) *Handler {
	v := &Handler{
		ChatStream: peerChatStream,
		cc:         chaincode,
	}
	v.responseChannel = make(map[string]chan pb.ChaincodeMessage)
	v.isTransaction = make(map[string]bool)
	v.nextState = make(chan *nextStateInfo)

	// Create the shim side FSM
	// @@ shim FSM 생성(finite state machine)
	v.FSM = fsm.NewFSM(
		"created",
		fsm.Events{
			{Name: pb.ChaincodeMessage_REGISTERED.String(), Src: []string{"created"}, Dst: "established"},
			{Name: pb.ChaincodeMessage_INIT.String(), Src: []string{"established"}, Dst: "init"},
			{Name: pb.ChaincodeMessage_READY.String(), Src: []string{"established"}, Dst: "ready"},
			{Name: pb.ChaincodeMessage_ERROR.String(), Src: []string{"init"}, Dst: "established"},
			{Name: pb.ChaincodeMessage_RESPONSE.String(), Src: []string{"init"}, Dst: "init"},
			{Name: pb.ChaincodeMessage_COMPLETED.String(), Src: []string{"init"}, Dst: "ready"},
			{Name: pb.ChaincodeMessage_TRANSACTION.String(), Src: []string{"ready"}, Dst: "transaction"},
			{Name: pb.ChaincodeMessage_COMPLETED.String(), Src: []string{"transaction"}, Dst: "ready"},
			{Name: pb.ChaincodeMessage_ERROR.String(), Src: []string{"transaction"}, Dst: "ready"},
			{Name: pb.ChaincodeMessage_RESPONSE.String(), Src: []string{"transaction"}, Dst: "transaction"},
			{Name: pb.ChaincodeMessage_QUERY.String(), Src: []string{"transaction"}, Dst: "transaction"},
			{Name: pb.ChaincodeMessage_QUERY.String(), Src: []string{"ready"}, Dst: "ready"},
			{Name: pb.ChaincodeMessage_RESPONSE.String(), Src: []string{"ready"}, Dst: "ready"},
		},
		fsm.Callbacks{
			"before_" + pb.ChaincodeMessage_REGISTERED.String(): func(e *fsm.Event) { v.beforeRegistered(e) },
			//"after_" + pb.ChaincodeMessage_INIT.String(): func(e *fsm.Event) { v.beforeInit(e) },
			//"after_" + pb.ChaincodeMessage_TRANSACTION.String(): func(e *fsm.Event) { v.beforeTransaction(e) },
			"after_" + pb.ChaincodeMessage_RESPONSE.String(): func(e *fsm.Event) { v.afterResponse(e) },
			"after_" + pb.ChaincodeMessage_ERROR.String():    func(e *fsm.Event) { v.afterError(e) },
			"enter_init":                                     func(e *fsm.Event) { v.enterInitState(e) },
			"enter_transaction":                              func(e *fsm.Event) { v.enterTransactionState(e) },
			//"enter_ready":                                     func(e *fsm.Event) { v.enterReadyState(e) },
			"before_" + pb.ChaincodeMessage_QUERY.String(): func(e *fsm.Event) { v.beforeQuery(e) }, //only checks for QUERY
		},
	)
	return v
}

// beforeRegistered is called to handle the REGISTERED message.
// @@ beforeRegistered : REGISTERED message를 다루기 위해 호출됨.
func (handler *Handler) beforeRegistered(e *fsm.Event) {
	if _, ok := e.Args[0].(*pb.ChaincodeMessage); !ok {
		e.Cancel(fmt.Errorf("Received unexpected message type"))
		return
	}
	chaincodeLogger.Debugf("Received %s, ready for invocations", pb.ChaincodeMessage_REGISTERED)
}

// handleInit handles request to initialize chaincode.
// handleInit : 체인코드 초기 설정 요청을 다룸.
func (handler *Handler) handleInit(msg *pb.ChaincodeMessage) {
	// The defer followed by triggering a go routine dance is needed to ensure that the previous state transition
	// is completed before the next one is triggered. The previous state transition is deemed complete only when
	// the beforeInit function is exited. Interesting bug fix!!
	go func() {
		var nextStateMsg *pb.ChaincodeMessage

		send := true

		defer func() {
			handler.triggerNextState(nextStateMsg, send)
		}()

		// Get the function and args from Payload
		// @@ 메세지의 payload를 구하기
		input := &pb.ChaincodeInput{}
		unmarshalErr := proto.Unmarshal(msg.Payload, input)
		if unmarshalErr != nil {
			payload := []byte(unmarshalErr.Error())
			// Send ERROR message to chaincode support and change state
			chaincodeLogger.Debugf("[%s]Incorrect payload format. Sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_ERROR)
			nextStateMsg = &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_ERROR, Payload: payload, Txid: msg.Txid}
			return
		}

		// Mark as a transaction (allow put/del state)
		// @@ 트랜잭션으로 마킹 -> 상태의 put, delete 허용
		handler.markIsTransaction(msg.Txid, true)

		// Call chaincode's Run
		// Create the ChaincodeStub which the chaincode can use to callback
		// @@ ChaincodeStub 객체를 새로 생성. -> 체인코드가 응답하기 위해 사용됨.
		stub := new(ChaincodeStub)
		stub.init(msg.Txid, msg.SecurityContext)
		function, params := getFunctionAndParams(stub)
		res, err := handler.cc.Init(stub, function, params)

		// delete isTransaction entry
		handler.deleteIsTransaction(msg.Txid)

		if err != nil {
			payload := []byte(err.Error())
			// Send ERROR message to chaincode support and change state
			chaincodeLogger.Errorf("[%s]Init failed. Sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_ERROR)
			nextStateMsg = &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_ERROR, Payload: payload, Txid: msg.Txid, ChaincodeEvent: stub.chaincodeEvent}
			return
		}

		// Send COMPLETED message to chaincode support and change state
		// @@ COMPLETED 메세지를 chaincode support에 전달하고, 상태를 변화시킴.
		nextStateMsg = &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_COMPLETED, Payload: res, Txid: msg.Txid, ChaincodeEvent: stub.chaincodeEvent}
		chaincodeLogger.Debugf("[%s]Init succeeded. Sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_COMPLETED)
	}()
}

// enterInitState will initialize the chaincode if entering init from established.
func (handler *Handler) enterInitState(e *fsm.Event) {
	chaincodeLogger.Debugf("Entered state %s", handler.FSM.Current())
	msg, ok := e.Args[0].(*pb.ChaincodeMessage)
	if !ok {
		e.Cancel(fmt.Errorf("Received unexpected message type"))
		return
	}
	chaincodeLogger.Debugf("[%s]Received %s, initializing chaincode", shorttxid(msg.Txid), msg.Type.String())
	if msg.Type.String() == pb.ChaincodeMessage_INIT.String() {
		// Call the chaincode's Run function to initialize
		// @@ 체인코드의 실행 펑션을 호출
		handler.handleInit(msg)
	}
}

// handleTransaction Handles request to execute a transaction.
// @@ handleTransaction : 트랜잭션을 실행하는 요청을 다룸.
func (handler *Handler) handleTransaction(msg *pb.ChaincodeMessage) {
	// The defer followed by triggering a go routine dance is needed to ensure that the previous state transition
	// is completed before the next one is triggered. The previous state transition is deemed complete only when
	// the beforeInit function is exited. Interesting bug fix!!
	go func() {
		//better not be nil
		var nextStateMsg *pb.ChaincodeMessage

		send := true

		defer func() {
			handler.triggerNextState(nextStateMsg, send)
		}()

		// Get the function and args from Payload
		input := &pb.ChaincodeInput{}
		unmarshalErr := proto.Unmarshal(msg.Payload, input)
		if unmarshalErr != nil {
			payload := []byte(unmarshalErr.Error())
			// Send ERROR message to chaincode support and change state
			chaincodeLogger.Debugf("[%s]Incorrect payload format. Sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_ERROR)
			nextStateMsg = &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_ERROR, Payload: payload, Txid: msg.Txid}
			return
		}

		// Mark as a transaction (allow put/del state)
		handler.markIsTransaction(msg.Txid, true)

		// Call chaincode's Run
		// Create the ChaincodeStub which the chaincode can use to callback
		stub := new(ChaincodeStub)
		stub.init(msg.Txid, msg.SecurityContext)
		function, params := getFunctionAndParams(stub)
		res, err := handler.cc.Invoke(stub, function, params)

		// delete isTransaction entry
		handler.deleteIsTransaction(msg.Txid)

		if err != nil {
			payload := []byte(err.Error())
			// Send ERROR message to chaincode support and change state
			chaincodeLogger.Errorf("[%s]Transaction execution failed. Sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_ERROR)
			nextStateMsg = &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_ERROR, Payload: payload, Txid: msg.Txid, ChaincodeEvent: stub.chaincodeEvent}
			return
		}

		// Send COMPLETED message to chaincode support and change state
		chaincodeLogger.Debugf("[%s]Transaction completed. Sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_COMPLETED)
		nextStateMsg = &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_COMPLETED, Payload: res, Txid: msg.Txid, ChaincodeEvent: stub.chaincodeEvent}
	}()
}

// handleQuery handles request to execute a query.
// @@ handleQuery : 쿼리를 실행하는 요청을 다룸
func (handler *Handler) handleQuery(msg *pb.ChaincodeMessage) {
	// Query does not transition state. It can happen anytime after Ready
	// @@ 쿼리는 상태 변화를 일으키지 않음.
	go func() {
		var serialSendMsg *pb.ChaincodeMessage

		defer func() {
			handler.serialSend(serialSendMsg)
		}()

		// Get the function and args from Payload
		input := &pb.ChaincodeInput{}
		unmarshalErr := proto.Unmarshal(msg.Payload, input)
		if unmarshalErr != nil {
			payload := []byte(unmarshalErr.Error())
			// Send ERROR message to chaincode support and change state
			chaincodeLogger.Debugf("[%s]Incorrect payload format. Sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_QUERY_ERROR)
			serialSendMsg = &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_QUERY_ERROR, Payload: payload, Txid: msg.Txid}
			return
		}

		// Mark as a query (do not allow put/del state)
		// @@ 쿼리로 마킹. 상태의 put과 delete를 허용하지 않음
		handler.markIsTransaction(msg.Txid, false)

		// Call chaincode's Query
		// Create the ChaincodeStub which the chaincode can use to callback
		// @@ 체인코드의 쿼리를 호출.
		stub := new(ChaincodeStub)
		stub.init(msg.Txid, msg.SecurityContext)
		function, params := getFunctionAndParams(stub)
		res, err := handler.cc.Query(stub, function, params)

		// delete isTransaction entry
		handler.deleteIsTransaction(msg.Txid)

		if err != nil {
			payload := []byte(err.Error())
			// Send ERROR message to chaincode support and change state
			chaincodeLogger.Errorf("[%s]Query execution failed. Sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_QUERY_ERROR)
			serialSendMsg = &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_QUERY_ERROR, Payload: payload, Txid: msg.Txid}
			return
		}

		// Send COMPLETED message to chaincode support
		chaincodeLogger.Debugf("[%s]Query completed. Sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_QUERY_COMPLETED)
		serialSendMsg = &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_QUERY_COMPLETED, Payload: res, Txid: msg.Txid}
	}()
}

// enterTransactionState will execute chaincode's Run if coming from a TRANSACTION event.
// @@ enterTransactionState : 트랜잭션 이벤트로 인한 체인코드의 run을 실행
func (handler *Handler) enterTransactionState(e *fsm.Event) {
	msg, ok := e.Args[0].(*pb.ChaincodeMessage)
	if !ok {
		e.Cancel(fmt.Errorf("Received unexpected message type"))
		return
	}
	chaincodeLogger.Debugf("[%s]Received %s, invoking transaction on chaincode(Src:%s, Dst:%s)", shorttxid(msg.Txid), msg.Type.String(), e.Src, e.Dst)
	if msg.Type.String() == pb.ChaincodeMessage_TRANSACTION.String() {
		// Call the chaincode's Run function to invoke transaction
		// 트랜잭션을 실행하기 위해 체인코드의 run 펑션을 호출.
		handler.handleTransaction(msg)
	}
}

// enterReadyState will need to handle COMPLETED event by sending message to the peer
//func (handler *Handler) enterReadyState(e *fsm.Event) {

// afterCompleted will need to handle COMPLETED event by sending message to the peer
// @@ afterCompleted : COMPLETED event를 peer에게 전달
func (handler *Handler) afterCompleted(e *fsm.Event) {
	msg, ok := e.Args[0].(*pb.ChaincodeMessage)
	if !ok {
		e.Cancel(fmt.Errorf("Received unexpected message type"))
		return
	}
	chaincodeLogger.Debugf("[%s]sending COMPLETED to validator for tid", shorttxid(msg.Txid))
	if err := handler.serialSend(msg); err != nil {
		e.Cancel(fmt.Errorf("send COMPLETED failed %s", err))
	}
}

// beforeQuery is invoked when a query message is received from the validator
// @@ beforeQuery : validator로부터 쿼리 메세지를 수신했을 때 실행됨.
func (handler *Handler) beforeQuery(e *fsm.Event) {
	if e.Args != nil {
		msg, ok := e.Args[0].(*pb.ChaincodeMessage)
		if !ok {
			e.Cancel(fmt.Errorf("Received unexpected message type"))
			return
		}
		handler.handleQuery(msg)
	}
}

// afterResponse is called to deliver a response or error to the chaincode stub.
// @@ afterResponse : chaincode stub에 응답이나 에러를 전달하기 위해 호출됨.
func (handler *Handler) afterResponse(e *fsm.Event) {
	msg, ok := e.Args[0].(*pb.ChaincodeMessage)
	if !ok {
		e.Cancel(fmt.Errorf("Received unexpected message type"))
		return
	}

	if err := handler.sendChannel(msg); err != nil {
		chaincodeLogger.Errorf("[%s]error sending %s (state:%s): %s", shorttxid(msg.Txid), msg.Type, handler.FSM.Current(), err)
	} else {
		chaincodeLogger.Debugf("[%s]Received %s, communicated (state:%s)", shorttxid(msg.Txid), msg.Type, handler.FSM.Current())
	}
}

// @@ validator로부터 에러를 수신했을 경우
func (handler *Handler) afterError(e *fsm.Event) {
	msg, ok := e.Args[0].(*pb.ChaincodeMessage)
	if !ok {
		e.Cancel(fmt.Errorf("Received unexpected message type"))
		return
	}

	/* TODO- revisit. This may no longer be needed with the serialized/streamlined messaging model
	 * There are two situations in which the ERROR event can be triggered:
	 * 1. When an error is encountered within handleInit or handleTransaction - some issue at the chaincode side; In this case there will be no responseChannel and the message has been sent to the validator.
	 * 2. The chaincode has initiated a request (get/put/del state) to the validator and is expecting a response on the responseChannel; If ERROR is received from validator, this needs to be notified on the responseChannel.
	 */
	// @@ 에러 트리거 : 1.handleInit 또는 handleTransaction시 에러 발생
	// @@ 체인코드가 validator에게 상태 변경에 대한 요청을 던졌을 때,  responseChannel로 응답을 기대. 만약 validator로부터 에러를 수신하게 되면, 이 에러는 responseChannel을 통해 알려져야 함.
	if err := handler.sendChannel(msg); err == nil {
		chaincodeLogger.Debugf("[%s]Error received from validator %s, communicated(state:%s)", shorttxid(msg.Txid), msg.Type, handler.FSM.Current())
	}
}

// TODO: Implement method to get and put entire state map and not one key at a time?
// handleGetState communicates with the validator to fetch the requested state information from the ledger.
// @@ handleGetState : validator와 소통하며 요청된 상태 정보를 렛저로부터 get
func (handler *Handler) handleGetState(key string, txid string) ([]byte, error) {
	// Create the channel on which to communicate the response from validating peer
	respChan, uniqueReqErr := handler.createChannel(txid)
	if uniqueReqErr != nil {
		chaincodeLogger.Debug("Another state request pending for this Txid. Cannot process.")
		return nil, uniqueReqErr
	}

	defer handler.deleteChannel(txid)

	// Send GET_STATE message to validator chaincode support
	// GET_STATE 메세지를 validator의 chaincode support로 전달
	payload := []byte(key)
	msg := &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_GET_STATE, Payload: payload, Txid: txid}
	chaincodeLogger.Debugf("[%s]Sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_GET_STATE)
	if err := handler.serialSend(msg); err != nil {
		chaincodeLogger.Errorf("[%s]error sending GET_STATE %s", shorttxid(txid), err)
		return nil, errors.New("could not send msg")
	}

	// Wait on responseChannel for response
	responseMsg, ok := handler.receiveChannel(respChan)
	if !ok {
		chaincodeLogger.Errorf("[%s]Received unexpected message type", shorttxid(responseMsg.Txid))
		return nil, errors.New("Received unexpected message type")
	}

	if responseMsg.Type.String() == pb.ChaincodeMessage_RESPONSE.String() {
		// Success response
		chaincodeLogger.Debugf("[%s]GetState received payload %s", shorttxid(responseMsg.Txid), pb.ChaincodeMessage_RESPONSE)
		return responseMsg.Payload, nil
	}
	if responseMsg.Type.String() == pb.ChaincodeMessage_ERROR.String() {
		// Error response
		chaincodeLogger.Errorf("[%s]GetState received error %s", shorttxid(responseMsg.Txid), pb.ChaincodeMessage_ERROR)
		return nil, errors.New(string(responseMsg.Payload[:]))
	}

	// Incorrect chaincode message received
	chaincodeLogger.Errorf("[%s]Incorrect chaincode message %s received. Expecting %s or %s", shorttxid(responseMsg.Txid), responseMsg.Type, pb.ChaincodeMessage_RESPONSE, pb.ChaincodeMessage_ERROR)
	return nil, errors.New("Incorrect chaincode message received")
}

// handlePutState communicates with the validator to put state information into the ledger.
func (handler *Handler) handlePutState(key string, value []byte, txid string) error {
	// Check if this is a transaction
	chaincodeLogger.Debugf("[%s]Inside putstate, isTransaction = %t", shorttxid(txid), handler.isTransaction[txid])
	if !handler.isTransaction[txid] {
		return errors.New("Cannot put state in query context")
	}

	payload := &pb.PutStateInfo{Key: key, Value: value}
	payloadBytes, err := proto.Marshal(payload)
	if err != nil {
		return errors.New("Failed to process put state request")
	}

	// Create the channel on which to communicate the response from validating peer
	respChan, uniqueReqErr := handler.createChannel(txid)
	if uniqueReqErr != nil {
		chaincodeLogger.Errorf("[%s]Another state request pending for this Txid. Cannot process.", shorttxid(txid))
		return uniqueReqErr
	}

	defer handler.deleteChannel(txid)

	// Send PUT_STATE message to validator chaincode support
	msg := &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_PUT_STATE, Payload: payloadBytes, Txid: txid}
	chaincodeLogger.Debugf("[%s]Sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_PUT_STATE)
	if err = handler.serialSend(msg); err != nil {
		chaincodeLogger.Errorf("[%s]error sending PUT_STATE %s", msg.Txid, err)
		return errors.New("could not send msg")
	}

	// Wait on responseChannel for response
	responseMsg, ok := handler.receiveChannel(respChan)
	if !ok {
		chaincodeLogger.Errorf("[%s]Received unexpected message type", msg.Txid)
		return errors.New("Received unexpected message type")
	}

	if responseMsg.Type.String() == pb.ChaincodeMessage_RESPONSE.String() {
		// Success response
		chaincodeLogger.Debugf("[%s]Received %s. Successfully updated state", shorttxid(responseMsg.Txid), pb.ChaincodeMessage_RESPONSE)
		return nil
	}

	if responseMsg.Type.String() == pb.ChaincodeMessage_ERROR.String() {
		// Error response
		chaincodeLogger.Errorf("[%s]Received %s. Payload: %s", shorttxid(responseMsg.Txid), pb.ChaincodeMessage_ERROR, responseMsg.Payload)
		return errors.New(string(responseMsg.Payload[:]))
	}

	// Incorrect chaincode message received
	chaincodeLogger.Errorf("[%s]Incorrect chaincode message %s received. Expecting %s or %s", shorttxid(responseMsg.Txid), responseMsg.Type, pb.ChaincodeMessage_RESPONSE, pb.ChaincodeMessage_ERROR)
	return errors.New("Incorrect chaincode message received")
}

// handleDelState communicates with the validator to delete a key from the state in the ledger.
func (handler *Handler) handleDelState(key string, txid string) error {
	// Check if this is a transaction
	if !handler.isTransaction[txid] {
		return errors.New("Cannot del state in query context")
	}

	// Create the channel on which to communicate the response from validating peer
	respChan, uniqueReqErr := handler.createChannel(txid)
	if uniqueReqErr != nil {
		chaincodeLogger.Errorf("[%s]Another state request pending for this Txid. Cannot process create createChannel.", shorttxid(txid))
		return uniqueReqErr
	}

	defer handler.deleteChannel(txid)

	// Send DEL_STATE message to validator chaincode support
	payload := []byte(key)
	msg := &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_DEL_STATE, Payload: payload, Txid: txid}
	chaincodeLogger.Debugf("[%s]Sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_DEL_STATE)
	if err := handler.serialSend(msg); err != nil {
		chaincodeLogger.Errorf("[%s]error sending DEL_STATE %s", shorttxid(msg.Txid), pb.ChaincodeMessage_DEL_STATE)
		return errors.New("could not send msg")
	}

	// Wait on responseChannel for response
	responseMsg, ok := handler.receiveChannel(respChan)
	if !ok {
		chaincodeLogger.Errorf("[%s]Received unexpected message type", shorttxid(msg.Txid))
		return errors.New("Received unexpected message type")
	}

	if responseMsg.Type.String() == pb.ChaincodeMessage_RESPONSE.String() {
		// Success response
		chaincodeLogger.Debugf("[%s]Received %s. Successfully deleted state", msg.Txid, pb.ChaincodeMessage_RESPONSE)
		return nil
	}
	if responseMsg.Type.String() == pb.ChaincodeMessage_ERROR.String() {
		// Error response
		chaincodeLogger.Errorf("[%s]Received %s. Payload: %s", msg.Txid, pb.ChaincodeMessage_ERROR, responseMsg.Payload)
		return errors.New(string(responseMsg.Payload[:]))
	}

	// Incorrect chaincode message received
	chaincodeLogger.Errorf("[%s]Incorrect chaincode message %s received. Expecting %s or %s", shorttxid(responseMsg.Txid), responseMsg.Type, pb.ChaincodeMessage_RESPONSE, pb.ChaincodeMessage_ERROR)
	return errors.New("Incorrect chaincode message received")
}

func (handler *Handler) handleRangeQueryState(startKey, endKey string, txid string) (*pb.RangeQueryStateResponse, error) {
	// Create the channel on which to communicate the response from validating peer
	respChan, uniqueReqErr := handler.createChannel(txid)
	if uniqueReqErr != nil {
		chaincodeLogger.Debugf("[%s]Another state request pending for this Txid. Cannot process.", shorttxid(txid))
		return nil, uniqueReqErr
	}

	defer handler.deleteChannel(txid)

	// Send RANGE_QUERY_STATE message to validator chaincode support
	payload := &pb.RangeQueryState{StartKey: startKey, EndKey: endKey}
	payloadBytes, err := proto.Marshal(payload)
	if err != nil {
		return nil, errors.New("Failed to process range query state request")
	}
	msg := &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_RANGE_QUERY_STATE, Payload: payloadBytes, Txid: txid}
	chaincodeLogger.Debugf("[%s]Sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_RANGE_QUERY_STATE)
	if err = handler.serialSend(msg); err != nil {
		chaincodeLogger.Errorf("[%s]error sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_RANGE_QUERY_STATE)
		return nil, errors.New("could not send msg")
	}

	// Wait on responseChannel for response
	responseMsg, ok := handler.receiveChannel(respChan)
	if !ok {
		chaincodeLogger.Errorf("[%s]Received unexpected message type", txid)
		return nil, errors.New("Received unexpected message type")
	}

	if responseMsg.Type.String() == pb.ChaincodeMessage_RESPONSE.String() {
		// Success response
		chaincodeLogger.Debugf("[%s]Received %s. Successfully got range", shorttxid(responseMsg.Txid), pb.ChaincodeMessage_RESPONSE)

		rangeQueryResponse := &pb.RangeQueryStateResponse{}
		unmarshalErr := proto.Unmarshal(responseMsg.Payload, rangeQueryResponse)
		if unmarshalErr != nil {
			chaincodeLogger.Errorf("[%s]unmarshall error", shorttxid(responseMsg.Txid))
			return nil, errors.New("Error unmarshalling RangeQueryStateResponse.")
		}

		return rangeQueryResponse, nil
	}
	if responseMsg.Type.String() == pb.ChaincodeMessage_ERROR.String() {
		// Error response
		chaincodeLogger.Errorf("[%s]Received %s", shorttxid(responseMsg.Txid), pb.ChaincodeMessage_ERROR)
		return nil, errors.New(string(responseMsg.Payload[:]))
	}

	// Incorrect chaincode message received
	chaincodeLogger.Errorf("Incorrect chaincode message %s recieved. Expecting %s or %s", responseMsg.Type, pb.ChaincodeMessage_RESPONSE, pb.ChaincodeMessage_ERROR)
	return nil, errors.New("Incorrect chaincode message received")
}

func (handler *Handler) handleRangeQueryStateNext(id, txid string) (*pb.RangeQueryStateResponse, error) {
	// Create the channel on which to communicate the response from validating peer
	respChan, uniqueReqErr := handler.createChannel(txid)
	if uniqueReqErr != nil {
		chaincodeLogger.Debugf("[%s]Another state request pending for this Txid. Cannot process.", shorttxid(txid))
		return nil, uniqueReqErr
	}

	defer handler.deleteChannel(txid)

	// Send RANGE_QUERY_STATE_NEXT message to validator chaincode support
	payload := &pb.RangeQueryStateNext{ID: id}
	payloadBytes, err := proto.Marshal(payload)
	if err != nil {
		return nil, errors.New("Failed to process range query state next request")
	}
	msg := &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_RANGE_QUERY_STATE_NEXT, Payload: payloadBytes, Txid: txid}
	chaincodeLogger.Debugf("[%s]Sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_RANGE_QUERY_STATE_NEXT)
	if err = handler.serialSend(msg); err != nil {
		chaincodeLogger.Errorf("[%s]error sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_RANGE_QUERY_STATE_NEXT)
		return nil, errors.New("could not send msg")
	}

	// Wait on responseChannel for response
	responseMsg, ok := handler.receiveChannel(respChan)
	if !ok {
		chaincodeLogger.Errorf("[%s]Received unexpected message type", txid)
		return nil, errors.New("Received unexpected message type")
	}

	if responseMsg.Type.String() == pb.ChaincodeMessage_RESPONSE.String() {
		// Success response
		chaincodeLogger.Debugf("[%s]Received %s. Successfully got range", shorttxid(responseMsg.Txid), pb.ChaincodeMessage_RESPONSE)

		rangeQueryResponse := &pb.RangeQueryStateResponse{}
		unmarshalErr := proto.Unmarshal(responseMsg.Payload, rangeQueryResponse)
		if unmarshalErr != nil {
			chaincodeLogger.Errorf("[%s]unmarshall error", shorttxid(responseMsg.Txid))
			return nil, errors.New("Error unmarshalling RangeQueryStateResponse.")
		}

		return rangeQueryResponse, nil
	}
	if responseMsg.Type.String() == pb.ChaincodeMessage_ERROR.String() {
		// Error response
		chaincodeLogger.Errorf("[%s]Received %s", shorttxid(responseMsg.Txid), pb.ChaincodeMessage_ERROR)
		return nil, errors.New(string(responseMsg.Payload[:]))
	}

	// Incorrect chaincode message received
	chaincodeLogger.Errorf("Incorrect chaincode message %s recieved. Expecting %s or %s", responseMsg.Type, pb.ChaincodeMessage_RESPONSE, pb.ChaincodeMessage_ERROR)
	return nil, errors.New("Incorrect chaincode message received")
}

func (handler *Handler) handleRangeQueryStateClose(id, txid string) (*pb.RangeQueryStateResponse, error) {
	// Create the channel on which to communicate the response from validating peer
	respChan, uniqueReqErr := handler.createChannel(txid)
	if uniqueReqErr != nil {
		chaincodeLogger.Debugf("[%s]Another state request pending for this Txid. Cannot process.", shorttxid(txid))
		return nil, uniqueReqErr
	}

	defer handler.deleteChannel(txid)

	// Send RANGE_QUERY_STATE_CLOSE message to validator chaincode support
	payload := &pb.RangeQueryStateClose{ID: id}
	payloadBytes, err := proto.Marshal(payload)
	if err != nil {
		return nil, errors.New("Failed to process range query state close request")
	}
	msg := &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_RANGE_QUERY_STATE_CLOSE, Payload: payloadBytes, Txid: txid}
	chaincodeLogger.Debugf("[%s]Sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_RANGE_QUERY_STATE_CLOSE)
	if err = handler.serialSend(msg); err != nil {
		chaincodeLogger.Errorf("[%s]error sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_RANGE_QUERY_STATE_CLOSE)
		return nil, errors.New("could not send msg")
	}

	// Wait on responseChannel for response
	responseMsg, ok := handler.receiveChannel(respChan)
	if !ok {
		chaincodeLogger.Errorf("[%s]Received unexpected message type", txid)
		return nil, errors.New("Received unexpected message type")
	}

	if responseMsg.Type.String() == pb.ChaincodeMessage_RESPONSE.String() {
		// Success response
		chaincodeLogger.Debugf("[%s]Received %s. Successfully got range", shorttxid(responseMsg.Txid), pb.ChaincodeMessage_RESPONSE)

		rangeQueryResponse := &pb.RangeQueryStateResponse{}
		unmarshalErr := proto.Unmarshal(responseMsg.Payload, rangeQueryResponse)
		if unmarshalErr != nil {
			chaincodeLogger.Errorf("[%s]unmarshall error", shorttxid(responseMsg.Txid))
			return nil, errors.New("Error unmarshalling RangeQueryStateResponse.")
		}

		return rangeQueryResponse, nil
	}
	if responseMsg.Type.String() == pb.ChaincodeMessage_ERROR.String() {
		// Error response
		chaincodeLogger.Errorf("[%s]Received %s", shorttxid(responseMsg.Txid), pb.ChaincodeMessage_ERROR)
		return nil, errors.New(string(responseMsg.Payload[:]))
	}

	// Incorrect chaincode message received
	chaincodeLogger.Errorf("Incorrect chaincode message %s recieved. Expecting %s or %s", responseMsg.Type, pb.ChaincodeMessage_RESPONSE, pb.ChaincodeMessage_ERROR)
	return nil, errors.New("Incorrect chaincode message received")
}

// handleInvokeChaincode communicates with the validator to invoke another chaincode.
// @@ handleInvokeChaincode : 또 다른 체인코드를 실행하기 위해 validator와 통신
func (handler *Handler) handleInvokeChaincode(chaincodeName string, args [][]byte, txid string) ([]byte, error) {
	// Check if this is a transaction
	if !handler.isTransaction[txid] {
		return nil, errors.New("Cannot invoke chaincode in query context")
	}

	chaincodeID := &pb.ChaincodeID{Name: chaincodeName}
	input := &pb.ChaincodeInput{Args: args}
	payload := &pb.ChaincodeSpec{ChaincodeID: chaincodeID, CtorMsg: input}
	payloadBytes, err := proto.Marshal(payload)
	if err != nil {
		return nil, errors.New("Failed to process invoke chaincode request")
	}

	// Create the channel on which to communicate the response from validating peer
	respChan, uniqueReqErr := handler.createChannel(txid)
	if uniqueReqErr != nil {
		chaincodeLogger.Errorf("[%s]Another request pending for this Txid. Cannot process.", txid)
		return nil, uniqueReqErr
	}

	defer handler.deleteChannel(txid)

	// Send INVOKE_CHAINCODE message to validator chaincode support
	msg := &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_INVOKE_CHAINCODE, Payload: payloadBytes, Txid: txid}
	chaincodeLogger.Debugf("[%s]Sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_INVOKE_CHAINCODE)
	if err = handler.serialSend(msg); err != nil {
		chaincodeLogger.Errorf("[%s]error sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_INVOKE_CHAINCODE)
		return nil, errors.New("could not send msg")
	}

	// Wait on responseChannel for response
	responseMsg, ok := handler.receiveChannel(respChan)
	if !ok {
		chaincodeLogger.Errorf("[%s]Received unexpected message type", shorttxid(msg.Txid))
		return nil, errors.New("Received unexpected message type")
	}

	if responseMsg.Type.String() == pb.ChaincodeMessage_RESPONSE.String() {
		// Success response
		chaincodeLogger.Debugf("[%s]Received %s. Successfully invoked chaincode", shorttxid(responseMsg.Txid), pb.ChaincodeMessage_RESPONSE)
		respMsg := &pb.ChaincodeMessage{}
		if err := proto.Unmarshal(responseMsg.Payload, respMsg); err != nil {
			chaincodeLogger.Errorf("[%s]Error unmarshaling called chaincode response: %s", shorttxid(responseMsg.Txid), err)
			return nil, err
		}
		if respMsg.Type == pb.ChaincodeMessage_COMPLETED {
			// Success response
			chaincodeLogger.Debugf("[%s]Received %s. Successfully invoed chaincode", shorttxid(responseMsg.Txid), pb.ChaincodeMessage_RESPONSE)
			return respMsg.Payload, nil
		}
		chaincodeLogger.Errorf("[%s]Received %s. Error from chaincode", shorttxid(responseMsg.Txid), respMsg.Type.String())
		return nil, errors.New(string(respMsg.Payload[:]))
	}
	if responseMsg.Type.String() == pb.ChaincodeMessage_ERROR.String() {
		// Error response
		chaincodeLogger.Errorf("[%s]Received %s.", shorttxid(responseMsg.Txid), pb.ChaincodeMessage_ERROR)
		return nil, errors.New(string(responseMsg.Payload[:]))
	}

	// Incorrect chaincode message received
	chaincodeLogger.Debugf("[%s]Incorrect chaincode message %s received. Expecting %s or %s", shorttxid(responseMsg.Txid), responseMsg.Type, pb.ChaincodeMessage_RESPONSE, pb.ChaincodeMessage_ERROR)
	return nil, errors.New("Incorrect chaincode message received")
}

// handleQueryChaincode communicates with the validator to query another chaincode.
// @@ handleQueryChaincode : validator가 또 다른 체인코드에 query를 수행할 수 있도록 통신
func (handler *Handler) handleQueryChaincode(chaincodeName string, args [][]byte, txid string) ([]byte, error) {
	chaincodeID := &pb.ChaincodeID{Name: chaincodeName}
	input := &pb.ChaincodeInput{Args: args}
	payload := &pb.ChaincodeSpec{ChaincodeID: chaincodeID, CtorMsg: input}
	payloadBytes, err := proto.Marshal(payload)
	if err != nil {
		return nil, errors.New("Failed to process query chaincode request")
	}

	// Create the channel on which to communicate the response from validating peer
	respChan, uniqueReqErr := handler.createChannel(txid)
	if uniqueReqErr != nil {
		chaincodeLogger.Debug("Another request pending for this Txid. Cannot process.")
		return nil, uniqueReqErr
	}

	defer handler.deleteChannel(txid)

	// Send INVOKE_QUERY message to validator chaincode support
	msg := &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_INVOKE_QUERY, Payload: payloadBytes, Txid: txid}
	chaincodeLogger.Debugf("[%s]Sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_INVOKE_QUERY)
	if err = handler.serialSend(msg); err != nil {
		chaincodeLogger.Errorf("[%s]error sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_INVOKE_QUERY)
		return nil, errors.New("could not send msg")
	}

	// Wait on responseChannel for response
	responseMsg, ok := handler.receiveChannel(respChan)
	if !ok {
		chaincodeLogger.Errorf("[%s]Received unexpected message type", shorttxid(msg.Txid))
		return nil, errors.New("Received unexpected message type")
	}

	if responseMsg.Type.String() == pb.ChaincodeMessage_RESPONSE.String() {
		respMsg := &pb.ChaincodeMessage{}
		if err := proto.Unmarshal(responseMsg.Payload, respMsg); err != nil {
			chaincodeLogger.Errorf("[%s]Error unmarshaling called chaincode responseP: %s", shorttxid(responseMsg.Txid), err)
			return nil, err
		}
		if respMsg.Type == pb.ChaincodeMessage_QUERY_COMPLETED {
			// Success response
			chaincodeLogger.Debugf("[%s]Received %s. Successfully queried chaincode", shorttxid(responseMsg.Txid), pb.ChaincodeMessage_RESPONSE)
			return respMsg.Payload, nil
		}
		chaincodeLogger.Errorf("[%s]Error from chaincode: %s", shorttxid(responseMsg.Txid), string(respMsg.Payload[:]))
		return nil, errors.New(string(respMsg.Payload[:]))
	}
	if responseMsg.Type.String() == pb.ChaincodeMessage_ERROR.String() {
		// Error response
		chaincodeLogger.Errorf("[%s]Received %s.", shorttxid(responseMsg.Txid), pb.ChaincodeMessage_ERROR)
		return nil, errors.New(string(responseMsg.Payload[:]))
	}

	// Incorrect chaincode message received
	chaincodeLogger.Errorf("[%s]Incorrect chaincode message %s recieved. Expecting %s or %s", shorttxid(responseMsg.Txid), responseMsg.Type, pb.ChaincodeMessage_RESPONSE, pb.ChaincodeMessage_ERROR)
	return nil, errors.New("Incorrect chaincode message received")
}

// handleMessage message handles loop for shim side of chaincode/validator stream.
// @@ handleMessage : chaincode와 validator간의 스트림 유지
//@@ 수신된 Event 가 현재 State 에서 발생될 수 없는 것이면, 에러 처리
//@@ handler.FSM 의 State 를 전이(transition)
//@@ 에러가 NoTransitionError 또는 CanceledError 이고,
//@@ embedded 에러 != nil 일 경우만 에러 리턴, 나머지는 모두 nil 리턴
func (handler *Handler) handleMessage(msg *pb.ChaincodeMessage) error {
	if msg.Type == pb.ChaincodeMessage_KEEPALIVE {
		// Received a keep alive message, we don't do anything with it for now
		// and it does not touch the state machine
		return nil
	}
	chaincodeLogger.Debugf("[%s]Handling ChaincodeMessage of type: %s(state:%s)", shorttxid(msg.Txid), msg.Type, handler.FSM.Current())
	//@@ 수신된 Event 가 현재 State 에서 발생될 수 없는 것이면, 에러 처리
	if handler.FSM.Cannot(msg.Type.String()) {
		errStr := fmt.Sprintf("[%s]Chaincode handler FSM cannot handle message (%s) with payload size (%d) while in state: %s", msg.Txid, msg.Type.String(), len(msg.Payload), handler.FSM.Current())
		err := errors.New(errStr)
		payload := []byte(err.Error())
		errorMsg := &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_ERROR, Payload: payload, Txid: msg.Txid}
		handler.serialSend(errorMsg)
		return err
	}
	//@@ ( 현재 상태 + event ) -> 다음 상태 결정
	//@@ Event 전처리 함수 실행
	//@@ 상태 전이가 완료되었다면, Event 후처리 함수 실행후 정상리턴
	//@@ 상태전이 함수 정의 : State 진입 함수 + Event 후처리 함수
	//@@ State 퇴출 함수 실행
	//@@ 상태전이 함수 실행 ( State 진입 함수 + Event 후처리 함수 )
	//@@ 상태전이 함수 실행결과 리턴
	err := handler.FSM.Event(msg.Type.String(), msg)
	//@@ 에러가 NoTransitionError 또는 CanceledError 이고,
	//@@ embedded 에러 != nil 일 경우만 에러 리턴, 나머지는 모두 nil 리턴 
	return filterError(err)
}

// filterError filters the errors to allow NoTransitionError and CanceledError to not propagate for cases where embedded Err == nil.
//@@ 에러가 NoTransitionError 또는 CanceledError 이고,
//@@ embedded 에러 != nil 일 경우만 에러 리턴, 나머지는 모두 nil 리턴 
func filterError(errFromFSMEvent error) error {
	if errFromFSMEvent != nil {
		if noTransitionErr, ok := errFromFSMEvent.(*fsm.NoTransitionError); ok {
			if noTransitionErr.Err != nil {
				// Only allow NoTransitionError's, all others are considered true error.
				return errFromFSMEvent
			}
		}
		if canceledErr, ok := errFromFSMEvent.(*fsm.CanceledError); ok {
			if canceledErr.Err != nil {
				// Only allow NoTransitionError's, all others are considered true error.
				return canceledErr
				//t.Error("expected only 'NoTransitionError'")
			}
			chaincodeLogger.Debugf("Ignoring CanceledError: %s", canceledErr)
		}
	}
	return nil
}

func getFunctionAndParams(stub ChaincodeStubInterface) (function string, params []string) {
	allargs := stub.GetStringArgs()
	function = ""
	params = []string{}
	if len(allargs) >= 1 {
		function = allargs[0]
		params = allargs[1:]
	}
	return
}
