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

package consensus

import (
	pb "github.com/hyperledger/fabric/protos"
)

// ExecutionConsumer allows callbacks from asycnhronous execution and statetransfer
//@@ ExecutionConsumer : 비동기식 실행과 상태 전이로 인한 콜백을 허용한다.
type ExecutionConsumer interface {
	Executed(tag interface{})                                // Called whenever Execute completes //@@ 실행 완료시 호출됨
	Committed(tag interface{}, target *pb.BlockchainInfo)    // Called whenever Commit completes  //@@ 코밋 완료시 호출됨
	RolledBack(tag interface{})                              // Called whenever a Rollback completes //@@ 롤백 완료시 호출됨
	StateUpdated(tag interface{}, target *pb.BlockchainInfo) // Called when state transfer completes, if target is nil, this indicates a failure and a new target should be supplied
	//@@ 상태 전이 완료시 호출됨, 타겟이 nil이라면, 이는 실패를 의미하는 것으로 새로운 타겟이 설정되어야만 한다.
}

// Consenter is used to receive messages from the network
// Every consensus plugin needs to implement this interface
//@@ Consenter는 네트워크로부터 메세지를 수신한다.
//@@ 플러그인될 모든 컨센서스는 이 메세지 수신 인터페이스를 구현해야만 한다.
type Consenter interface {
	RecvMsg(msg *pb.Message, senderHandle *pb.PeerID) error // Called serially with incoming messages from gRPC //@@ gRPC를 통한 입력 메세지로 순차적으로 호출된다.
	ExecutionConsumer
}

// Inquirer is used to retrieve info about the validating network
//@@ Inquirer은 validater(컨센서스에 관여하는 피어)간의 네트워크 정보를 조회한다.
type Inquirer interface {
	GetNetworkInfo() (self *pb.PeerEndpoint, network []*pb.PeerEndpoint, err error)
	GetNetworkHandles() (self *pb.PeerID, network []*pb.PeerID, err error)
}

// Communicator is used to send messages to other validators
//@@ Communicator는 다른 validator들에게 메세지를 보내는데 쓰임, 방식은 broadcast, unicast 두 가지가 있음
type Communicator interface {
	Broadcast(msg *pb.Message, peerType pb.PeerEndpoint_Type) error
	Unicast(msg *pb.Message, receiverHandle *pb.PeerID) error
}

// NetworkStack is used to retrieve network info and send messages
//@@ NetworkStack은 네트워크 정보를 조회하고 메세지를 보내는데 쓰임
type NetworkStack interface {
	Communicator
	Inquirer
}

// SecurityUtils is used to access the sign/verify methods from the crypto package
//@@ SecurityUtils : 암호화 패키지의 서명과 검증 메소드에 접근하기 위해 쓰임
	Sign(msg []byte) ([]byte, error)
	Verify(peerID *pb.PeerID, signature []byte, message []byte) error
}

// ReadOnlyLedger is used for interrogating the blockchain
//@@ReadOnlyLedger는 블록체인에 질의를 던지기 위해 쓰임.
type ReadOnlyLedger interface {
	GetBlock(id uint64) (block *pb.Block, err error)
	GetBlockchainSize() uint64
	GetBlockchainInfo() *pb.BlockchainInfo
	GetBlockchainInfoBlob() []byte
	GetBlockHeadMetadata() ([]byte, error)
}

// LegacyExecutor is used to invoke transactions, potentially modifying the backing ledger
//@@ LegacyExecutor는 invoke 트랜잭션에 사용된다. ???
type LegacyExecutor interface {
	BeginTxBatch(id interface{}) error
	ExecTxs(id interface{}, txs []*pb.Transaction) ([]byte, error)
	CommitTxBatch(id interface{}, metadata []byte) (*pb.Block, error)
	RollbackTxBatch(id interface{}) error
	PreviewCommitTxBatch(id interface{}, metadata []byte) ([]byte, error)
}

// Executor is intended to eventually supplant the old Executor interface
// The problem with invoking the calls directly above, is that they must be coordinated
// with state transfer, to eliminate possible races and ledger corruption
//@@ Executor는 구 Executor 인터페이스를 대체하기 위한 새로운 인터페이스
//@@ 구 버전에서는 렛저의 무결성을 위하여 Invoking 호출시, 언제나 상태 전이를 같이 전달해야 했음
type Executor interface {
	Start()                                                                     // Bring up the resources needed to use this interface
	Halt()                                                                      // Tear down the resources needed to use this interface
	Execute(tag interface{}, txs []*pb.Transaction)                             // Executes a set of transactions, this may be called in succession
	Commit(tag interface{}, metadata []byte)                                    // Commits whatever transactions have been executed
	Rollback(tag interface{})                                                   // Rolls back whatever transactions have been executed
	UpdateState(tag interface{}, target *pb.BlockchainInfo, peers []*pb.PeerID) // Attempts to synchronize state to a particular target, implicitly calls rollback if needed
}

// LedgerManager is used to manipulate the state of the ledger
//@@ LedgerManager : 렛저의 상태를 조작학기 위해 쓰임.
type LedgerManager interface {
	InvalidateState() // Invalidate informs the ledger that it is out of date and should reject queries
	//@@ Invalidate는 렛저에 유효시간이 지났고, 쿼리를 거부해야 한다고 렛저에 알린다. 즉 렛저가 latest 상태가 아닌 경우.
	ValidateState() // Validate informs the ledger that it is back up to date and should resume replying to queries
	//@@ Validate는 현재 렛저가 최신의 상태를 유지하고 있고 입력된 쿼리에 응답해야 한다고 렛저에 알린다.
}

// StatePersistor is used to store consensus state which should survive a process crash
//@@ StatePersistor : 컨센서스 상태를 저장하기 위해 쓰이며, 프로세스에 문제가 생기는 상황에서도 무결성을 유지해야 한다.
type StatePersistor interface {
	StoreState(key string, value []byte) error
	ReadState(key string) ([]byte, error)
	ReadStateSet(prefix string) (map[string][]byte, error)
	DelState(key string)
}

// Stack is the set of stack-facing methods available to the consensus plugin
//@@ Stack은 플러그인된 컨센서스에게 제공되어지는 stack-facing 메소드의 집합이다. -> 가장 최상단의 인터페이스
type Stack interface {
	NetworkStack
	SecurityUtils
	Executor
	LegacyExecutor
	LedgerManager
	ReadOnlyLedger
	StatePersistor
}
