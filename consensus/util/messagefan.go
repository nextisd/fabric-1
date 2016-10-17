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

package util

import (
	"sync"

	"github.com/op/go-logging"

	pb "github.com/hyperledger/fabric/protos"
)

var logger *logging.Logger // package-level logger

func init() {
	logger = logging.MustGetLogger("consensus/util")
}

// Message encapsulates an OpenchainMessage with sender information
//@@ Message는 송신자 정보를 포함한 OpenchainMessage를 캡슐화 하였음
type Message struct {
	Msg    *pb.Message
	Sender *pb.PeerID
}

// MessageFan contains the reference to the peer's MessageHandlerCoordinator
//@@ MessageFan은 피어의 MessageHandlerCoordinator에 대한 참조를 포함.
type MessageFan struct {
	ins  []<-chan *Message
	out  chan *Message
	lock sync.Mutex
}

// NewMessageFan will return an initialized MessageFan
//@@ NewMessageFan은 위의 MessageFan을 초기화하여 리턴.
func NewMessageFan() *MessageFan {
	return &MessageFan{
		ins: []<-chan *Message{},
		out: make(chan *Message),
	}
}

// AddFaninChannel is intended to be invoked by Handler to add a channel to be fan-ed in
//@@ AddFaninChannel : 핸들러에 의해서 실행되도록 되어 있으며, fan-ed in될 채널을 추가한다.
func (fan *MessageFan) AddFaninChannel(channel <-chan *Message) {
	fan.lock.Lock()
	defer fan.lock.Unlock()

	for _, c := range fan.ins { //피어메세지 수신 채널 리스트
		if c == channel {
			logger.Warningf("Received duplicate connection")
			return
		}
	}

	fan.ins = append(fan.ins, channel)

	go func() {
		for msg := range channel {
			fan.out <- msg
		}

		fan.lock.Lock()
		defer fan.lock.Unlock()

		for i, c := range fan.ins {
			if c == channel {
				fan.ins = append(fan.ins[:i], fan.ins[i+1:]...)
			}
		}
	}()
}

// GetOutChannel returns a read only channel which the registered channels fan into
//@@ GetOutChannel: 읽기만 가능한 송신 채널을 리턴.
func (fan *MessageFan) GetOutChannel() <-chan *Message {
	return fan.out
}
