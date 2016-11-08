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

package producer

import (
	"fmt"
	"io"
	"time"

	pb "github.com/hyperledger/fabric/protos"
	"github.com/op/go-logging"
)

const defaultTimeout = time.Second * 3

var producerLogger = logging.MustGetLogger("eventhub_producer")

// EventsServer implementation of the Peer service
type EventsServer struct {
}

//singleton - if we want to create multiple servers, we need to subsume events.gEventConsumers into EventsServer
//이벤트 서버는 싱글톤으로 선언된다.
var globalEventsServer *EventsServer

// NewEventsServer returns a EventsServer
//새로운 이벤트 서버를 생성
func NewEventsServer(bufferSize uint, timeout int) *EventsServer {
	if globalEventsServer != nil {
		panic("Cannot create multiple event hub servers")
	}
	globalEventsServer = new(EventsServer)
	initializeEvents(bufferSize, timeout)
	//initializeCCEventProcessor(bufferSize, timeout)
	return globalEventsServer
}

// Chat implementation of the the Chat bidi streaming RPC function
//@@ stream 에서 받은 event를 처리하는 handler 객체 생성 (ChatStream = stream)
//@@ stream에서 Recv()
//@@ handler.HandleMessage 호출
//@@ 	Event_Register    수신 : 전역변수 gEventProcessor 의 이벤트별 핸들러리스트에 등록
//@@										 handler 의 interestedEvents (map) 에 event 추가
//@@ 	Event_Unregister 수신 : 전역변수 gEventProcessor 의 이벤트별 핸들러리스트에서 삭제
//@@										 handler 의 interestedEvents (map) 에서 event 삭제
//@@ 	ChatStream 으로 받은 msg 를 그대로 다시 돌려보냄?? --> 이상타!!
func (p *EventsServer) Chat(stream pb.Events_ChatServer) error {
	//새로운 이벤트 핸들러 생성
	handler, err := newEventHandler(stream)
	if err != nil {
		return fmt.Errorf("Error creating handler during handleChat initiation: %s", err)
	}
	defer handler.Stop()
	//서버의 chat stream으로 컨수머의 event를 수신, 정상적으로 수신했을 경우, 핸들러의 handlemessage call
	for {
		in, err := stream.Recv()
		if err == io.EOF {
			producerLogger.Debug("Received EOF, ending Chat")
			return nil
		}
		if err != nil {
			e := fmt.Errorf("Error during Chat, stopping handler: %s", err)
			producerLogger.Error(e.Error())
			return e
		}
		//@@ Event_Register    수신 : 전역변수 gEventProcessor 의 이벤트별 핸들러리스트에 등록
		//@@									 handler 의 interestedEvents (map) 에 event 추가
		//@@ Event_Unregister 수신 : 전역변수 gEventProcessor 의 이벤트별 핸들러리스트에서 삭제
		//@@									 handler 의 interestedEvents (map) 에서 event 삭제
		//@@ ChatStream 으로 받은 msg 를 그대로 다시 돌려보냄?? --> 이상타!!
		err = handler.HandleMessage(in)
		if err != nil {
			producerLogger.Errorf("Error handling message: %s", err)
			return err
		}

	}
}
