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

package helper

import (
	"github.com/hyperledger/fabric/consensus"
	"github.com/hyperledger/fabric/core/peer"

	"fmt"
	"sync"

	"github.com/hyperledger/fabric/consensus/controller"
	"github.com/hyperledger/fabric/consensus/util"
	"github.com/hyperledger/fabric/core/chaincode"
	pb "github.com/hyperledger/fabric/protos"
	"golang.org/x/net/context"
)

// EngineImpl implements a struct to hold consensus.Consenter, PeerEndpoint and MessageFan
//
// EngineImpl 구조체 : consensus.Consenter, helper, PeerEndPoint, MessageFan 구현
type EngineImpl struct {
	consenter    consensus.Consenter
	helper       *Helper
	peerEndpoint *pb.PeerEndpoint
	consensusFan *util.MessageFan
}

// GetHandlerFactory returns new NewConsensusHandler
//
// eng.GetHandlerFactory() : NewconsensusHandler 리턴, peer.HandlerFactory를 핸들러로 사용함(아래 참조)
// peer.HandlerFactory : type HandlerFactory func(MessageHandlerCoordinator, ChatStream, bool) (MessageHandler, error)
//
// type MessageHandlerCoordinator interface {
//	Peer
//	SecurityAccessor
//	BlockChainAccessor
//	BlockChainModifier
//	BlockChainUtil
//	StateAccessor
//	RegisterHandler(messageHandler MessageHandler) error
//	DeregisterHandler(messageHandler MessageHandler) error
//	Broadcast(*pb.Message, pb.PeerEndpoint_Type) []error
//	Unicast(*pb.Message, *pb.PeerID) error
//	GetPeers() (*pb.PeersMessage, error)
//	GetRemoteLedger(receiver *pb.PeerID) (RemoteLedger, error)
//	PeersDiscovered(*pb.PeersMessage) error
//	ExecuteTransaction(transaction *pb.Transaction) *pb.Response
//	Discoverer
//}
func (eng *EngineImpl) GetHandlerFactory() peer.HandlerFactory {
	return NewConsensusHandler
}

// ProcessTransactionMsg processes a Message in context of a Transaction
//
// eng.ProcessTransactionMsg() : 트랜잭션의 컨텍스트에 있는 메시지를 실행
//@@ Tx Type == Transaction_CHAINCODE_QUERY
//@@		chaincode.Execute() 호출
//@@ Tx Type != Transaction_CHAINCODE_QUERY
//@@		Response_SUCCESS msg 생성
//@@		consenter 가 없으면 리턴 ( Tx 결과는 나중에 다른 consenter로부터 수신 )
//@@		consenter 가 있으면 eng.consenter.RecvMsg() 호출
//@@			메시지 type을 CONSENSUS 로 변경하고, VP들에게 Broadcast.
//@@			CONSENSUS msg 일 경우, Tx 을 추출하여 go channel 로 전송
func (eng *EngineImpl) ProcessTransactionMsg(msg *pb.Message, tx *pb.Transaction) (response *pb.Response) {
	//TODO: Do we always verify security, or can we supply a flag on the invoke ot this functions so to bypass check for locally generated transactions?
	//
	// TODO : 항상 보안 검증을 하거나 아니면 로컬에서 생성된 invoke-function에 대한 bypass를 처리할 flag를 써보는건 어떨지?
	if tx.Type == pb.Transaction_CHAINCODE_QUERY {
		if !engine.helper.valid {
			logger.Warning("Rejecting query because state is currently not valid")
			return &pb.Response{Status: pb.Response_FAILURE,
				Msg: []byte("Error: state may be inconsistent, cannot query")}
		}

		// The secHelper is set during creat ChaincodeSupport, so we don't need this step
		// cxt := context.WithValue(context.Background(), "security", secHelper)
		cxt := context.Background()
		//query will ignore events as these are not stored on ledger (and query can report
		//"event" data synchronously anyway)
		//@@ ledger (blockchain) 관리 객체 얻어옴 (객체는 전역 1개)
		//@@ Confidentiality check
		//@@ CHAINCODE_DEPLOY 인 경우
		//@@		chain.Deploy(ctxt, t) 호출
		//@@			Dup Check
		//@@			VMCProcess() 호출 : 내부에서 vm.Deploy() 실행
		//@@		chain.Launch(ctxt, t) 호출
		//@@			launchAndWaitForRegister() 실행
		//@@				container.StartImageReq 생성후 VMCProcesS() 실행 ( 내부 : vm.Start() )
		//@@				readyNotify 채널에서 true 가 오면 정상, false 가 오면 실패
		//@@			sendInitOrReady() 실행
		//@@				handler.nextState 채널로 ChaincodeMessage 전송 & responseNotifier 생성
		//@@				응답수신 대기 && 에러응답 처리
		//@@ CHAINCODE_INVOKE  또는 CHAINCODE_QUERY 인 경우
		//@@		chain.Launch(ctxt, t) 호출
		//@@			launchAndWaitForRegister() 실행
		//@@				container.StartImageReq 생성후 VMCProcesS() 실행 ( 내부 : vm.Start() )
		//@@				readyNotify 채널에서 true 가 오면 정상, false 가 오면 실패
		//@@			sendInitOrReady() 실행
		//@@				handler.nextState 채널로 ChaincodeMessage 전송 & responseNotifier 생성
		//@@				응답수신 대기 && 에러응답 처리
		//@@			ChaincodeID, CtorMsg, err 리턴
		//@@		INVOKE 또는 QUERY 용 Tx Msg 생성
		//@@		chain.Execute(ctxt, chaincode, ccMsg, timeout, t) 호출
		//@@			ChaincodeID 로 *chaincodeRTEnv 를 찾지 못하면 에러 처리
		//@@			pb.Transaction 으로부터 pb.ChaincodeMessage.SecurityContext(msg) 설정
		//@@			chrte.handler.sendExecuteMessage() 실행 --> response 채널 얻기
		//@@ 			Tx == Transaction : handler.nextState 채널로 ChaincodeMessage 전송
		//@@ 			Tx != Transaction : serialSend : 체인코드 메세지를 순차적으로 송신. (Lock 처리)
		//@@ 			response 채널 리턴
		//@@			select : response 채널 과 timeout 채널
		//@@			handler 에서 Txid 를 삭제
		//@@			response 리턴
		//@@		return resp.Payload, resp.ChaincodeEvent,err
		result, _, err := chaincode.Execute(cxt, chaincode.GetChain(chaincode.DefaultChain), tx)
		if err != nil {
			response = &pb.Response{Status: pb.Response_FAILURE,
				Msg: []byte(fmt.Sprintf("Error:%s", err))}
		} else {
			response = &pb.Response{Status: pb.Response_SUCCESS, Msg: result}
		}
	} else {
		// 메시지가 CHAINCODE_QUERY가 아니라면(DEPLOY/INVOKE/TERMINATE?)
		// Chaincode Transaction
		response = &pb.Response{Status: pb.Response_SUCCESS, Msg: []byte(tx.Txid)}

		//TODO: Do we need to verify security, or can we supply a flag on the invoke ot this functions
		// If we fail to marshal or verify the tx, don't send it to consensus plugin
		// TODO : 보안 검증을 하거나, 아니면 invoke-function에 대한 flag를 써보는건 어떨지?
		// 만약 tx를 마샬링 또는 검증에 실패하면 컨센서스 플러그인에 보내면 안됨.
		// but 위에서 Reponse_SUCCESS를 Status에 넣어놨는데??
		if response.Status == pb.Response_FAILURE {
			return response
		}

		// Pass the message to the consenter (eg. PBFT) NOTE: Make sure engine has been initialized
		//
		// 메시지를 consenter에게 전달(e.g. PBFT) NOTE: engine이 초기화 후 전달해야됨.
		if eng.consenter == nil {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte("Engine not initialized")}
		}
		// TODO, do we want to put these requests into a queue? This will block until
		// the consenter gets around to handling the message, but it also provides some
		// natural feedback to the REST API to determine how long it takes to queue messages
		//
		// TODO : 위의 request들을 queue에다가 넣을건가??
		// consenter가 메시지를 핸들링하는 동안 REST API 처리는 지연될 수 있음.
		//@@ 메시지 type을 CONSENSUS 로 변경하고, VP들에게 Broadcast.
		//@@ CONSENSUS msg 일 경우, Tx 을 추출하여 go channel 로 전송
		err := eng.consenter.RecvMsg(msg, eng.peerEndpoint.ID)
		if err != nil {
			response = &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}
		}
	}
	return response
}

func (eng *EngineImpl) setConsenter(consenter consensus.Consenter) *EngineImpl {
	eng.consenter = consenter
	return eng
}

func (eng *EngineImpl) setPeerEndpoint(peerEndpoint *pb.PeerEndpoint) *EngineImpl {
	eng.peerEndpoint = peerEndpoint
	return eng
}

var engineOnce sync.Once

var engine *EngineImpl

func getEngineImpl() *EngineImpl {
	return engine
}

// GetEngine returns initialized peer.Engine
// GetEngine() : peer.Engine을 초기화 한 뒤 리턴
// 	peer.Engine 인터페이스 : 피어의 네트워크 통신 핸들링, 트랜잭션 처리 관리
//  VP 서버 기동시 같이 기동되는 듯 : peerServer, err = peer.NewPeerWithEngine(secHelperFunc, helper.GetEngine)
func GetEngine(coord peer.MessageHandlerCoordinator) (peer.Engine, error) {
	var err error
	engineOnce.Do(func() {
		engine = new(EngineImpl)
		engine.helper = NewHelper(coord)
		engine.consenter = controller.NewConsenter(engine.helper)
		engine.helper.setConsenter(engine.consenter)
		engine.peerEndpoint, err = coord.GetPeerEndpoint()
		engine.consensusFan = util.NewMessageFan()

		go func() {
			logger.Debug("Starting up message thread for consenter")

			// The channel never closes, so this should never break
			//
			// 아래 채널은 close 되지 않음, 항상 메시지 수신.
			for msg := range engine.consensusFan.GetOutChannel() {
				engine.consenter.RecvMsg(msg.Msg, msg.Sender)
			}
		}()
	})
	return engine, err
}
