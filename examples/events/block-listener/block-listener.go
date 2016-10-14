/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/hyperledger/fabric/events/consumer"
	pb "github.com/hyperledger/fabric/protos"
)

type adapter struct {
	notfy              chan *pb.Event_Block
	rejected           chan *pb.Event_Rejection
	cEvent             chan *pb.Event_ChaincodeEvent
	listenToRejections bool
	chaincodeID        string
}

//@@ consumer.EventAdapter : "github.com/hyperledger/fabric/events/consumer"
//EventAdapter is the interface by which a openchain event client registers interested events and
//receives messages from the openchain event Server

/* type EventAdapter interface {
	GetInterestedEvents() ([]*ehpb.Interest, error)
	Recv(msg *ehpb.Event) (bool, error)
	Disconnected(err error)
}*/
//@@fabric/protos/events.proto
/*enum EventType {
   	REGISTER = 0;
    BLOCK = 1;
	CHAINCODE = 2;
	REJECTION = 3;
}*/

//GetInterestedEvents implements consumer.EventAdapter interface for registering interested events
// @@ GetInterestedEvents :  관심 이벤트 등록 구현
func (a *adapter) GetInterestedEvents() ([]*pb.Interest, error) {
	if a.chaincodeID != "" {
		return []*pb.Interest{
			{EventType: pb.EventType_BLOCK},
			{EventType: pb.EventType_REJECTION},
			{EventType: pb.EventType_CHAINCODE,
				RegInfo: &pb.Interest_ChaincodeRegInfo{
					ChaincodeRegInfo: &pb.ChaincodeReg{
						ChaincodeID: a.chaincodeID,
						EventName:   ""}}}}, nil
	}
	return []*pb.Interest{{EventType: pb.EventType_BLOCK}, {EventType: pb.EventType_REJECTION}}, nil
}

//Recv implements consumer.EventAdapter interface for receiving events
//@@ Recv : 이벤트 수신 구현
//@@ 이벤트 등록을 제외하고, 등록 후 발생할 수 있는 정의된 이벤트 타입별로(Block, Rejection, chaincode)
//@@ 이벤트 메세지를 set
func (a *adapter) Recv(msg *pb.Event) (bool, error) {
	if o, e := msg.Event.(*pb.Event_Block); e {
		a.notfy <- o
		return true, nil
	}
	if o, e := msg.Event.(*pb.Event_Rejection); e {
		if a.listenToRejections {
			a.rejected <- o
		}
		return true, nil
	}
	if o, e := msg.Event.(*pb.Event_ChaincodeEvent); e {
		a.cEvent <- o
		return true, nil
	}
	return false, fmt.Errorf("Receive unkown type event: %v", msg)
}

//Disconnected implements consumer.EventAdapter interface for disconnecting
//@@ Disconnected : 이벤트 송수신 스트림chat 연결 해제

func (a *adapter) Disconnected(err error) {
	fmt.Printf("Disconnected...exiting\n")
	os.Exit(1)
}

//@@event -> consumer의 NewEventsClient객체를 참조하는 obcEHCleint를 선언하고,
//@@이 클라이언트를 실행.
//@@실행하게 되면, Event Hub와 연결을 생성하고, 관심 이벤트를 등록하게 된다.
func createEventClient(eventAddress string, listenToRejections bool, cid string) *adapter {
	var obcEHClient *consumer.EventsClient

	done := make(chan *pb.Event_Block)
	reject := make(chan *pb.Event_Rejection)
	adapter := &adapter{notfy: done, rejected: reject, listenToRejections: listenToRejections, chaincodeID: cid, cEvent: make(chan *pb.Event_ChaincodeEvent)}
	obcEHClient, _ = consumer.NewEventsClient(eventAddress, 5, adapter)
	if err := obcEHClient.Start(); err != nil {
		fmt.Printf("could not start chat %s\n", err)
		obcEHClient.Stop()
		return nil
	}

	return adapter
}

//블록 이벤트를 감지하는 메인 함수
func main() {
	var eventAddress string
	var listenToRejections bool
	var chaincodeID string
	//@@ 7053포트가 event hub?
	flag.StringVar(&eventAddress, "events-address", "0.0.0.0:7053", "address of events server")
	flag.BoolVar(&listenToRejections, "listen-to-rejections", false, "whether to listen to rejection events")
	flag.StringVar(&chaincodeID, "events-from-chaincode", "", "listen to events from given chaincode")
	flag.Parse()

	fmt.Printf("Event Address: %s\n", eventAddress)
	//이벤트 수신 클라이언트 생성
	a := createEventClient(eventAddress, listenToRejections, chaincodeID)
	if a == nil {
		fmt.Printf("Error creating event client\n")
		return
	}

	for {
		select {
		case b := <-a.notfy: //블록 메세지
			fmt.Printf("\n")
			fmt.Printf("\n")
			fmt.Printf("Received block\n")
			fmt.Printf("--------------\n")
			for _, r := range b.Block.Transactions {
				fmt.Printf("Transaction:\n\t[%v]\n", r)
			}
		case r := <-a.rejected: // 트랜잭션 리젝션 메세지
			fmt.Printf("\n")
			fmt.Printf("\n")
			fmt.Printf("Received rejected transaction\n")
			fmt.Printf("--------------\n")
			fmt.Printf("Transaction error:\n%s\t%s\n", r.Rejection.Tx.Txid, r.Rejection.ErrorMsg)
		case ce := <-a.cEvent: //체인코드 이벤트 메세지
			fmt.Printf("\n")
			fmt.Printf("\n")
			fmt.Printf("Received chaincode event\n")
			fmt.Printf("------------------------\n")
			fmt.Printf("Chaincode Event:%v\n", ce)
		}
	}
}
