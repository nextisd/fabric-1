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
	"strconv"

	pb "github.com/hyperledger/fabric/protos"
)

//핸들러는 실질적인 이벤트 송수신자간의 연결 정보를 가지고 있음
type handler struct {
	ChatStream       pb.Events_ChatServer
	interestedEvents map[string]*pb.Interest
}

//이벤트 핸들러 생성
func newEventHandler(stream pb.Events_ChatServer) (*handler, error) {
	//chat server -> 실제 피어에게 이벤트를 송신하는 서버
	d := &handler{
		ChatStream: stream,
	}
	//해당 핸들러가 핸들링한 이벤트 타입을 셋팅.
	d.interestedEvents = make(map[string]*pb.Interest)
	return d, nil
}

// Stop stops this handler
//핸들러 실행 종료
func (d *handler) Stop() error {
	d.deregisterAll()
	d.interestedEvents = nil
	return nil
}

//관심 이벤트 타입별로 key를 설정.
func getInterestKey(interest pb.Interest) string {
	var key string
	switch interest.EventType {
	case pb.EventType_BLOCK:
		key = "/" + strconv.Itoa(int(pb.EventType_BLOCK))
	case pb.EventType_REJECTION:
		key = "/" + strconv.Itoa(int(pb.EventType_REJECTION))
	case pb.EventType_CHAINCODE:
		key = "/" + strconv.Itoa(int(pb.EventType_CHAINCODE)) + "/" + interest.GetChaincodeRegInfo().ChaincodeID + "/" + interest.GetChaincodeRegInfo().EventName
	default:
		producerLogger.Errorf("unknown interest type %s", interest.EventType)
	}
	return key
}

//핸들러는 관심있는 이벤트을 등록.
func (d *handler) register(iMsg []*pb.Interest) error {
	// Could consider passing interest array to registerHandler
	// and only lock once for entire array here
	for _, v := range iMsg {
		if err := registerHandler(v, d); err != nil {
			producerLogger.Errorf("could not register %s: %s", v, err)
			continue
		}
		d.interestedEvents[getInterestKey(*v)] = v
	}

	return nil
}

//기 등록된 관심이벤트를 해제.
func (d *handler) deregister(iMsg []*pb.Interest) error {
	for _, v := range iMsg {
		if err := deRegisterHandler(v, d); err != nil {
			producerLogger.Errorf("could not deregister %s", v)
			continue
		}
		delete(d.interestedEvents, getInterestKey(*v))
	}
	return nil
}

//등록된 모든 관심 이벤트를 등록 해제
func (d *handler) deregisterAll() {
	for k, v := range d.interestedEvents {
		if err := deRegisterHandler(v, d); err != nil {
			producerLogger.Errorf("could not deregister %s", v)
			continue
		}
		delete(d.interestedEvents, k)
	}
}

// HandleMessage handles the Openchain messages for the Peer.
// 이벤트 메세지를 수신시,
// 등록이나 등록 해제와 관련된 경우는 핸들러의 등록 및 등록해제 펑션을 수행하고,
// 그외 실제 이벤트 메세지의 경우는, 해당 이벤트를 chatserver객체로 보낸다.
func (d *handler) HandleMessage(msg *pb.Event) error {
	//producerLogger.Debug("Handling Event")
	switch msg.Event.(type) {
	case *pb.Event_Register:
		eventsObj := msg.GetRegister()
		if err := d.register(eventsObj.Events); err != nil {
			return fmt.Errorf("Could not register events %s", err)
		}
	case *pb.Event_Unregister:
		eventsObj := msg.GetUnregister()
		if err := d.deregister(eventsObj.Events); err != nil {
			return fmt.Errorf("Could not unregister events %s", err)
		}
	case nil:
	default:
		return fmt.Errorf("Invalide type from client %T", msg.Event)
	}
	//TODO return supported events.. for now just return the received msg
	if err := d.ChatStream.Send(msg); err != nil {
		return fmt.Errorf("Error sending response to %v:  %s", msg, err)
	}

	return nil
}

// SendMessage sends a message to the remote PEER through the stream
// 핸들러가 가진 chatserver를 통해 원격 피어들에게 이벤트 메세지를 보낸다.
func (d *handler) SendMessage(msg *pb.Event) error {
	err := d.ChatStream.Send(msg)
	if err != nil {
		return fmt.Errorf("Error Sending message through ChatStream: %s", err)
	}
	return nil
}
