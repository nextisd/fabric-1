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

package consumer

import (
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/hyperledger/fabric/core/comm"
	ehpb "github.com/hyperledger/fabric/protos"
)

//EventsClient holds the stream and adapter for consumer to work with
//이벤트 클라이언트는 grpc client stream를 보유하고, 컨수머의 이벤트를 수용할 아답터I/F를 가지고 있음
type EventsClient struct {
	sync.RWMutex
	peerAddress string
	regTimeout  time.Duration
	stream      ehpb.Events_ChatClient
	adapter     EventAdapter
}

//NewEventsClient Returns a new grpc.ClientConn to the configured local PEER.
//새로운 이벤트 클라언언트는 로컬 피어 address를 받아서 해당 피어에 grpc 클라이언트를 구성한다.
func NewEventsClient(peerAddress string, regTimeout time.Duration, adapter EventAdapter) (*EventsClient, error) {
	var err error
	//시간 제한 있음
	if regTimeout < 100*time.Millisecond {
		regTimeout = 100 * time.Millisecond
		err = fmt.Errorf("regTimeout >= 0, setting to 100 msec")
	} else if regTimeout > 60*time.Second {
		regTimeout = 60 * time.Second
		err = fmt.Errorf("regTimeout > 60, setting to 60 sec")
	}
	return &EventsClient{sync.RWMutex{}, peerAddress, regTimeout, nil, adapter}, err
}

//newEventsClientConnectionWithAddress Returns a new grpc.ClientConn to the configured local PEER.
//클라이언트와 코넥션 맺음. TLS여부를 확인
func newEventsClientConnectionWithAddress(peerAddress string) (*grpc.ClientConn, error) {
	if comm.TLSEnabled() {
		return comm.NewClientConnectionWithAddress(peerAddress, true, true, comm.InitTLSForPeer())
	}
	return comm.NewClientConnectionWithAddress(peerAddress, true, false, nil)
}

func (ec *EventsClient) send(emsg *ehpb.Event) error {
	ec.Lock()
	defer ec.Unlock()
	return ec.stream.Send(emsg)
}

// RegisterAsync - registers interest in a event and doesn't wait for a response
// 비동기식 레지스터 : 관심 이벤트를 등록하는 등록 이벤트를 날리고, 응답은 기다리지 않는 비동기식 처리.
func (ec *EventsClient) RegisterAsync(ies []*ehpb.Interest) error {
	emsg := &ehpb.Event{Event: &ehpb.Event_Register{Register: &ehpb.Register{Events: ies}}}
	var err error
	if err = ec.send(emsg); err != nil {
		fmt.Printf("error on Register send %s\n", err)
	}
	return err
}

// register - registers interest in a event
// 동기식 레지스터 : 관심 이벤트를 등록
func (ec *EventsClient) register(ies []*ehpb.Interest) error {
	var err error
	if err = ec.RegisterAsync(ies); err != nil {
		return err
	}

	regChan := make(chan struct{})
	go func() {
		defer close(regChan)
		in, inerr := ec.stream.Recv()
		if inerr != nil {
			err = inerr
			return
		}

		switch in.Event.(type) {
		case *ehpb.Event_Register:
		case nil:
			err = fmt.Errorf("invalid nil object for register")
		default:
			err = fmt.Errorf("invalid registration object")
		}
	}()
	select {
	case <-regChan: //정상적인 레지스터
	case <-time.After(ec.regTimeout): //레지스터 타임 아웃시 에러 처리
		err = fmt.Errorf("timeout waiting for registration")
	}
	return err
}

// UnregisterAsync - Unregisters interest in a event and doesn't wait for a response
// 비동기식 등록 해제 : 관심 이벤트를 등록 해제 요청을 날리고 응답은 기다리지 않음.
func (ec *EventsClient) UnregisterAsync(ies []*ehpb.Interest) error {
	emsg := &ehpb.Event{Event: &ehpb.Event_Unregister{Unregister: &ehpb.Unregister{Events: ies}}}
	var err error
	if err = ec.send(emsg); err != nil {
		err = fmt.Errorf("error on unregister send %s\n", err)
	}

	return err
}

// unregister - unregisters interest in a event
// 관심 이벤트 등록 해제
func (ec *EventsClient) unregister(ies []*ehpb.Interest) error {
	var err error
	//비동기식 등록 해제 메세지를 날리고,
	if err = ec.UnregisterAsync(ies); err != nil {
		return err
	}
	//채널을 연 후,
	regChan := make(chan struct{})
	go func() {
		defer close(regChan)          //채널 클로즈를 기 예약.
		in, inerr := ec.stream.Recv() // 서버로부터 수신
		if inerr != nil {
			err = inerr
			return
		}
		switch in.Event.(type) {
		case *ehpb.Event_Unregister: //정상적인 등록 해제를 받은 경우,
		case nil: //등록 해제할 대상이 없는 경우.
			err = fmt.Errorf("invalid nil object for unregister")
		default: //유효하지 않은 등록 해제
			err = fmt.Errorf("invalid unregistration object")
		}
	}()
	select {
	case <-regChan:
	case <-time.After(ec.regTimeout): //이벤트 수신 타임 아웃
		err = fmt.Errorf("timeout waiting for unregistration")
	}
	return err
}

// Recv recieves next event - use when client has not called Start
// 이벤트 수신 대기.
func (ec *EventsClient) Recv() (*ehpb.Event, error) {
	in, err := ec.stream.Recv() // 이벤트를 in으로 받음.
	if err == io.EOF {
		// read done.
		if ec.adapter != nil {
			ec.adapter.Disconnected(nil)
		}
		return nil, err
	}
	if err != nil {
		if ec.adapter != nil {
			ec.adapter.Disconnected(err)
		}
		return nil, err
	}
	return in, nil
}

// 이벤트 처리.
func (ec *EventsClient) processEvents() error {
	defer ec.stream.CloseSend()
	for {
		in, err := ec.stream.Recv() //클라이언트 수신 stream으로 이벤트 받으면(in), 이벤트를 읽은 후,

		if err == io.EOF {
			// read done.
			if ec.adapter != nil {
				ec.adapter.Disconnected(nil)
			}
			return nil
		}
		if err != nil {
			if ec.adapter != nil {
				ec.adapter.Disconnected(err)
			}
			return err
		}
		if ec.adapter != nil { // 클라이언트의 아답터 I/F를 통해 내용(cont)을 보낸다.
			cont, err := ec.adapter.Recv(in)
			if !cont {
				return err
			}
		}
	}
}

//Start establishes connection with Event hub and registers interested events with it
//이벤트 허브(server)와 연결을 맺고, 관심 이벤트를 등록한다.
func (ec *EventsClient) Start() error {
	conn, err := newEventsClientConnectionWithAddress(ec.peerAddress)
	if err != nil {
		return fmt.Errorf("Could not create client conn to %s", ec.peerAddress)
	}

	ies, err := ec.adapter.GetInterestedEvents()
	if err != nil {
		return fmt.Errorf("error getting interested events:%s", err)
	}

	if len(ies) == 0 {
		return fmt.Errorf("must supply interested events")
	}

	serverClient := ehpb.NewEventsClient(conn)
	ec.stream, err = serverClient.Chat(context.Background())
	if err != nil {
		return fmt.Errorf("Could not create client conn to %s", ec.peerAddress)
	}
	//관심이벤트를 가져와서(ies) 등록.
	if err = ec.register(ies); err != nil {
		return err
	}

	go ec.processEvents()

	return nil
}

//Stop terminates connection with event hub
func (ec *EventsClient) Stop() error {
	if ec.stream == nil {
		// in case the steam/chat server has not been established earlier, we assume that it's closed, successfully
		return nil
	}
	return ec.stream.CloseSend()
}
