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

//This package defines the interfaces that support runtime and
//communication between chaincode and peer (chaincode support).
//Currently inproccontroller uses it. dockercontroller does not.
//  ccintf 패키지 : 체인코드와 피어간의 런타임/통신 인터페이스를 정의함
//  현재는 inproccontrollse 패키지 에서 사용중임(dockercontroller 에서는 미사용)
package ccintf

import (
	pb "github.com/hyperledger/fabric/protos"
	"golang.org/x/net/context"
)

// ChaincodeStream interface for stream between Peer and chaincode instance.
//
// Chaincodestream interface : peer와 chaincode instance 사이의 스트림에 대한 인터페이스.
type ChaincodeStream interface {
	Send(*pb.ChaincodeMessage) error
	Recv() (*pb.ChaincodeMessage, error)
}

// CCSupport must be implemented by the chaincode support side in peer
// (such as chaincode_support)
//
// CCSupport interface : 피어단의 체인코드 지원 소스코드에서 반드시 구현되어야 함(e.g. chaincode_support.go)
// QQQ. ?? 해당 코드에 구현 안되어 있음
type CCSupport interface {
	HandleChaincodeStream(context.Context, ChaincodeStream) error
}

// GetCCHandlerKey is used to pass CCSupport via context
//
// GetCCHandlerKey() : 컨텍스트를 통해 CCSupport을 전달.
func GetCCHandlerKey() string {
	return "CCHANDLER"
}

//CCID encapsulates chaincode ID
// CCID구조체 : 는 체인코드ID를 캡슐화 시킴, VM 구동시 사용.
type CCID struct {
	ChaincodeSpec *pb.ChaincodeSpec
	NetworkID     string
	PeerID        string
}
