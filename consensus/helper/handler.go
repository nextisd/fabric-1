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
	"fmt"

	"github.com/op/go-logging"
	"github.com/spf13/viper"

	"github.com/hyperledger/fabric/consensus/util"
	"github.com/hyperledger/fabric/core/peer"

	pb "github.com/hyperledger/fabric/protos"
)

var logger *logging.Logger // package-level logger

func init() {
	logger = logging.MustGetLogger("consensus/handler")
}

const (
	// DefaultConsensusQueueSize value of 1000
	DefaultConsensusQueueSize int = 1000
)

// ConsensusHandler handles consensus messages.
// It also implements the Stack.
//
// ConsensusHandler 구조체 : 컨센서스 메시지 핸들링, consensus.stack 구현.
type ConsensusHandler struct {
	// type MessageHandler interface {
	//	RemoteLedger
	//	HandleMessage(msg *pb.Message) error
	//	SendMessage(msg *pb.Message) error
	//	To() (pb.PeerEndpoint, error)
	//	Stop() error
	//  }
	peer.MessageHandler
	consenterChan chan *util.Message // Msg *pb.Message, Sender *pb.PeerID

	// 등록된 MessageHandler간 coordination 처리
	coordinator peer.MessageHandlerCoordinator
}

// NewConsensusHandler constructs a new MessageHandler for the plugin.
// Is instance of peer.HandlerFactory
//
// NewConsensusHandler() : 플러그인된 컨센서스에 대한 새로운 MessageHandler 생성.
// peer.HandlerFactory의 객체임.
func NewConsensusHandler(coord peer.MessageHandlerCoordinator,
	stream peer.ChatStream, initiatedStream bool) (peer.MessageHandler, error) {

	peerHandler, err := peer.NewPeerHandler(coord, stream, initiatedStream)
	if err != nil {
		return nil, fmt.Errorf("Error creating PeerHandler: %s", err)
	}

	handler := &ConsensusHandler{
		MessageHandler: peerHandler,
		coordinator:    coord,
	}

	consensusQueueSize := viper.GetInt("peer.validator.consensus.buffersize")

	if consensusQueueSize <= 0 {
		logger.Errorf("peer.validator.consensus.buffersize is set to %d, but this must be a positive integer, defaulting to %d", consensusQueueSize, DefaultConsensusQueueSize)
		consensusQueueSize = DefaultConsensusQueueSize
	}

	// config 길이만큼 consenter 메시지 채널 생성
	handler.consenterChan = make(chan *util.Message, consensusQueueSize)

	//type EngineImpl struct {
	//	consenter    consensus.Consenter
	//	helper       *Helper
	//	peerEndpoint *pb.PeerEndpoint
	//	consensusFan *util.MessageFan (피어의 MessageHandlerCoordinator 참조값: {ins/out channel, lock sync.Mutex})
	//	}
	// AddFaninchannel() : AddFaninChannel is intended to be invoked by Handler to add a channel to be fan-ed in.
	// AddFaninchannel은 채널에 fan-ed in(컨센서스 대상 peer인듯) 되게 하기 위해 Handler에 의해 invoke 되도록 만들어짐.
	getEngineImpl().consensusFan.AddFaninChannel(handler.consenterChan)

	return handler, nil
}

// HandleMessage handles the incoming Fabric messages for the Peer
//
// handler.HandlerMessage() : 피어에게 수신되는 fabric 메시지들을 핸들링
func (handler *ConsensusHandler) HandleMessage(msg *pb.Message) error {

	if msg.Type == pb.Message_CONSENSUS {
		senderPE, _ := handler.To()
		select {
		// CONSESUS 메시지일 경우 msg와 Sender의 peerID를 consenter채널로 보낸다
		case handler.consenterChan <- &util.Message{
			Msg:    msg,
			Sender: senderPE.ID,
		}:
			return nil
		// consenter 메시지 채널이 꽉 찼을경우 에러처리
		default:
			err := fmt.Errorf("Message channel for %v full, rejecting", senderPE.ID)
			logger.Errorf("Failed to queue consensus message because: %v", err)
			return err
		}
	}

	// 아무것도 하지 않고, 다음 MessageHandler에게 msg를 넘겨줌
	if logger.IsEnabledFor(logging.DEBUG) {
		logger.Debugf("Did not handle message of type %s, passing on to next MessageHandler", msg.Type)
	}
	return handler.MessageHandler.HandleMessage(msg)
}
