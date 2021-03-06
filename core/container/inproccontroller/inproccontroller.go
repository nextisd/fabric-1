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

// system chaincode 용 vm controller.
package inproccontroller

import (
	"fmt"
	"io"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/core/container/ccintf"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/op/go-logging"

	"golang.org/x/net/context"
)

type inprocContainer struct {
	chaincode shim.Chaincode
	running   bool
	args      []string
	env       []string
	stopChan  chan struct{}
}

var (
	inprocLogger = logging.MustGetLogger("inproccontroller")
	typeRegistry = make(map[string]*inprocContainer)
	instRegistry = make(map[string]*inprocContainer)
)

//Register registers system chaincode with given path. The deploy should be called to initialize
//Register함수는 주어진 경로에 시스템 체인코드를 등록함. 초기화를 위해 deploy를 호출해야함.
//@@ 전역변수 typeRegistry ( map[string]*inprocContainer ) 에 system chaincode 등록
func Register(path string, cc shim.Chaincode) error {
	tmp := typeRegistry[path]
	if tmp != nil {
		return fmt.Errorf(fmt.Sprintf("%s is registered", path))
	}

	typeRegistry[path] = &inprocContainer{chaincode: cc}
	return nil
}

//InprocVM is a vm. It is identified by a executable name
//InprocVM은 excutable name으로 구별되는 vm임.
type InprocVM struct {
	id string
}

// 체인코드 인스턴스 생성 및 instRegistry (Map) 에 등록
//@@ instRegistry (Map) 에 등록되어 있다면 warning --> 하지만 정상 리턴
//@@ inprocContainer 생성 및 instRegistry ( map[string]*inprocContainer ) 에 추가
func (vm *InprocVM) getInstance(ctxt context.Context, ipctemplate *inprocContainer, ccid ccintf.CCID, args []string, env []string) (*inprocContainer, error) {
	ipc := instRegistry[ccid.ChaincodeSpec.ChaincodeID.Name]
	//@@ instRegistry (Map) 에 등록되어 있다면 warning --> 하지만 정상 리턴
	if ipc != nil {
		inprocLogger.Warningf("chaincode instance exists for %s", ccid.ChaincodeSpec.ChaincodeID.Name)
		return ipc, nil
	}
	//@@ inprocContainer 생성 및 instRegistry (Map) 에 등록
	ipc = &inprocContainer{args: args, env: env, chaincode: ipctemplate.chaincode, stopChan: make(chan struct{})}
	instRegistry[ccid.ChaincodeSpec.ChaincodeID.Name] = ipc
	inprocLogger.Debugf("chaincode instance created for %s", ccid.ChaincodeSpec.ChaincodeID.Name)
	return ipc, nil
}

//Deploy verifies chaincode is registered and creates an instance for it. Currently only one instance can be created
//Deploy함수는 체인코드 등록여부검증 및 해당 체인코드의 인스턴스를 생성함.
//현재는 한개의 인스턴스만 생성 가능.
//@@ typeRegistry ( map[string]*inprocContainer ) 에 존재하는지 확인
//@@ inprocContainer 생성 및 instRegistry ( map[string]*inprocContainer ) 에 추가
func (vm *InprocVM) Deploy(ctxt context.Context, ccid ccintf.CCID, args []string, env []string, attachstdin bool, attachstdout bool, reader io.Reader) error {
	path := ccid.ChaincodeSpec.ChaincodeID.Path

	ipctemplate := typeRegistry[path]
	if ipctemplate == nil {
		return fmt.Errorf(fmt.Sprintf("%s not registered. Please register the system chaincode in inprocinstances.go", path))
	}

	if ipctemplate.chaincode == nil {
		return fmt.Errorf(fmt.Sprintf("%s system chaincode does not contain chaincode instance", path))
	}

	// 체인코드 인스턴스 생성 및 instRegistry (Map) 에 등록
	_, err := vm.getInstance(ctxt, ipctemplate, ccid, args, env)

	//FUTURE ... here is where we might check code for safety
	//추후에... 여기서 코드 체크 필요.
	inprocLogger.Debugf("registered : %s", path)

	return err
}

//@@ peerRcvCCSend, peerRcvCCSend 채널 생성
//@@ StartInProc() 실행
//@@ 	peer 로 "REGISTER 요청" 송신 ( handler.ChatStream.Send() 실행 (Lock 처리) )
//@@ 	stream.Recv() 호출 : stream 에서 메시지 수신 ( + 에러처리 )
//@@ 	handler.nextState 에서 들어온 메시지 처리 : handler.FSM 의 State 를 전이(transition)
//@@ HandleChaincodeStream() 실행
//@@ 	handler.processStream() 실행
//@@ 		handler.ChatStream.Recv() 실행 : stream 에서 데이터 수신
//@@ 		( 통신 에러 및 Data 에러 ) 처리
//@@ 		keep alive 인 경우, 다시 수신 시도
//@@ 		keep alive timeout 발생시, KEEPALIVE 요청 송신
//@@ 		handler.HandleMessage() 호출 : 수신한 ChaincodeMessage 에 대한 처리
//@@ 			QUERY_COMPLETED : Tracking대상에서 삭제 -> Payload 암호화 -> handler.responseNotifier 로 msg 전달
//@@ 			QUERY_ERROR : Tracking대상에서 삭제 -> handler.responseNotifier 로 msg 전달
//@@ 			INVOKE_QUERY : chaincode 실행 & 응답 처리 
//@@ 									-> handler.nextState 채널로 ChaincodeMessage 송신 및 응답 처리
//@@ 			수신된 Event 가 현재 State 에서 발생될 수 없는 것이면, 에러 처리
//@@ 			handler.FSM 의 State 를 전이(transition)
//@@ 		handler.nextState 채널에서 이벤트 발생 && Chaincode 로 응답을 보내줘야 한다면
//@@ 		nsInfo.msg 을 handler.ChatStream 을 통해 전송
//@@ select : ccchan, ccsupportchan, ipc.stopChan --> channel close
func (ipc *inprocContainer) launchInProc(ctxt context.Context, id string, args []string, env []string, ccSupport ccintf.CCSupport) error {
	peerRcvCCSend := make(chan *pb.ChaincodeMessage)
	ccRcvPeerSend := make(chan *pb.ChaincodeMessage)
	var err error
	ccchan := make(chan struct{}, 1)
	ccsupportchan := make(chan struct{}, 1)
	go func() {
		defer close(ccchan)
		inprocLogger.Debugf("chaincode started for %s", id)
		if args == nil {
			args = ipc.args
		}
		if env == nil {
			env = ipc.env
		}
		// shim.StartInProc() : 시스템 체인코드 bootstrap entry point, chaincode용 API는 아님
		//@@ StartInProc() 실행
		//@@		chatWithPeer() 호출
		//@@			peer 로 "REGISTER 요청" 송신 ( handler.ChatStream.Send() 실행 (Lock 처리) )
		//@@			stream.Recv() 호출 : stream 에서 메시지 수신 ( + 에러처리 )
		//@@			handler.nextState 에서 들어온 메시지 처리 : handler.FSM 의 State 를 전이(transition)
		err := shim.StartInProc(env, args, ipc.chaincode, ccRcvPeerSend, peerRcvCCSend)
		if err != nil {
			err = fmt.Errorf("chaincode-support ended with err: %s", err)
			inprocLogger.Errorf("%s", err)
		}
		inprocLogger.Debugf("chaincode ended with for  %s with err: %s", id, err)
	}()

	go func() {
		defer close(ccsupportchan)
		inprocStream := newInProcStream(peerRcvCCSend, ccRcvPeerSend)
		inprocLogger.Debugf("chaincode-support started for  %s", id)
		//@@ HandleChaincodeStream() 실행
		//@@ 	handler.processStream() 실행
		//@@ 		handler.ChatStream.Recv() 실행 : stream 에서 데이터 수신
		//@@ 		( 통신 에러 및 Data 에러 ) 처리
		//@@ 		keep alive 인 경우, 다시 수신 시도
		//@@ 		keep alive timeout 발생시, KEEPALIVE 요청 송신
		//@@ 		handler.HandleMessage() 호출 : 수신한 ChaincodeMessage 에 대한 처리
		//@@ 			QUERY_COMPLETED : Tracking대상에서 삭제 -> Payload 암호화 -> handler.responseNotifier 로 msg 전달
		//@@ 			QUERY_ERROR : Tracking대상에서 삭제 -> handler.responseNotifier 로 msg 전달
		//@@ 			INVOKE_QUERY : chaincode 실행 & 응답 처리 
		//@@ 									-> handler.nextState 채널로 ChaincodeMessage 송신 및 응답 처리
		//@@ 			수신된 Event 가 현재 State 에서 발생될 수 없는 것이면, 에러 처리
		//@@ 			handler.FSM 의 State 를 전이(transition)
		//@@ 		handler.nextState 채널에서 이벤트 발생 && Chaincode 로 응답을 보내줘야 한다면
		//@@ 		nsInfo.msg 을 handler.ChatStream 을 통해 전송
		err := ccSupport.HandleChaincodeStream(ctxt, inprocStream)
		if err != nil {
			err = fmt.Errorf("chaincode ended with err: %s", err)
			inprocLogger.Errorf("%s", err)
		}
		inprocLogger.Debugf("chaincode-support ended with for  %s with err: %s", id, err)
	}()

	select {
	case <-ccchan:
		close(peerRcvCCSend)
		inprocLogger.Debugf("chaincode %s quit", id)
	case <-ccsupportchan:
		close(ccRcvPeerSend)
		inprocLogger.Debugf("chaincode support %s quit", id)
	case <-ipc.stopChan:
		close(ccRcvPeerSend)
		close(peerRcvCCSend)
		inprocLogger.Debugf("chaincode %s stopped", id)
	}

	return err
}

//Start starts a previously registered system codechain
//Start함수는 사전에 등록된 시스템 체인코드를 실행함.
//@@ vm.getInstance() 호출
//@@		instRegistry (Map) 에 등록되어 있다면 warning --> 하지만 정상 리턴
//@@		inprocContainer 생성 및 instRegistry ( map[string]*inprocContainer ) 에 추가
//@@ launchInProc() 호출
//@@		peerRcvCCSend, peerRcvCCSend 채널 생성
//@@		StartInProc() 실행
//@@			chatWithPeer() 호출
//@@ 			peer 로 "REGISTER 요청" 송신 ( handler.ChatStream.Send() 실행 (Lock 처리) )
//@@ 			stream.Recv() 호출 : stream 에서 메시지 수신 ( + 에러처리 )
//@@ 			handler.nextState 에서 들어온 메시지 처리 : handler.FSM 의 State 를 전이(transition)
//@@		HandleChaincodeStream() 실행
//@@ 		handler.processStream() 실행
//@@ 			handler.ChatStream.Recv() 실행 : stream 에서 데이터 수신
//@@ 			( 통신 에러 및 Data 에러 ) 처리
//@@ 			keep alive 인 경우, 다시 수신 시도
//@@ 			keep alive timeout 발생시, KEEPALIVE 요청 송신
//@@ 			handler.HandleMessage() 호출 : 수신한 ChaincodeMessage 에 대한 처리
//@@ 				QUERY_COMPLETED : Tracking대상에서 삭제 -> Payload 암호화 -> handler.responseNotifier 로 msg 전달
//@@ 				QUERY_ERROR : Tracking대상에서 삭제 -> handler.responseNotifier 로 msg 전달
//@@ 				INVOKE_QUERY : chaincode 실행 & 응답 처리 
//@@ 										-> handler.nextState 채널로 ChaincodeMessage 송신 및 응답 처리
//@@ 				수신된 Event 가 현재 State 에서 발생될 수 없는 것이면, 에러 처리
//@@ 				handler.FSM 의 State 를 전이(transition)
//@@ 			handler.nextState 채널에서 이벤트 발생 && Chaincode 로 응답을 보내줘야 한다면
//@@ 			nsInfo.msg 을 handler.ChatStream 을 통해 전송
//@@		select : ccchan, ccsupportchan, ipc.stopChan --> channel close
func (vm *InprocVM) Start(ctxt context.Context, ccid ccintf.CCID, args []string, env []string, attachstdin bool, attachstdout bool, reader io.Reader) error {
	path := ccid.ChaincodeSpec.ChaincodeID.Path

	ipctemplate := typeRegistry[path]

	if ipctemplate == nil {
		return fmt.Errorf(fmt.Sprintf("%s not registered", path))
	}

	//@@ instRegistry (Map) 에 등록되어 있다면 warning --> 하지만 정상 리턴
	//@@ inprocContainer 생성 및 instRegistry ( map[string]*inprocContainer ) 에 추가
	ipc, err := vm.getInstance(ctxt, ipctemplate, ccid, args, env)

	if err != nil {
		return fmt.Errorf(fmt.Sprintf("could not create instance for %s", ccid.ChaincodeSpec.ChaincodeID.Name))
	}

	if ipc.running {
		return fmt.Errorf(fmt.Sprintf("chaincode running %s", path))
	}

	//TODO VALIDITY CHECKS ?

	ccSupport, ok := ctxt.Value(ccintf.GetCCHandlerKey()).(ccintf.CCSupport)
	if !ok || ccSupport == nil {
		return fmt.Errorf("in-process communication generator not supplied")
	}

	ipc.running = true

	go func() {
		defer func() {
			if r := recover(); r != nil {
				inprocLogger.Criticalf("caught panic from chaincode  %s", ccid.ChaincodeSpec.ChaincodeID.Name)
			}
		}()
		//@@ peerRcvCCSend, peerRcvCCSend 채널 생성
		//@@ StartInProc() 실행
		//@@		chatWithPeer() 호출
		//@@ 		peer 로 "REGISTER 요청" 송신 ( handler.ChatStream.Send() 실행 (Lock 처리) )
		//@@ 		stream.Recv() 호출 : stream 에서 메시지 수신 ( + 에러처리 )
		//@@ 		handler.nextState 에서 들어온 메시지 처리 : handler.FSM 의 State 를 전이(transition)
		//@@ HandleChaincodeStream() 실행
		//@@ 	handler.processStream() 실행
		//@@ 		handler.ChatStream.Recv() 실행 : stream 에서 데이터 수신
		//@@ 		( 통신 에러 및 Data 에러 ) 처리
		//@@ 		keep alive 인 경우, 다시 수신 시도
		//@@ 		keep alive timeout 발생시, KEEPALIVE 요청 송신
		//@@ 		handler.HandleMessage() 호출 : 수신한 ChaincodeMessage 에 대한 처리
		//@@ 			QUERY_COMPLETED : Tracking대상에서 삭제 -> Payload 암호화 -> handler.responseNotifier 로 msg 전달
		//@@ 			QUERY_ERROR : Tracking대상에서 삭제 -> handler.responseNotifier 로 msg 전달
		//@@ 			INVOKE_QUERY : chaincode 실행 & 응답 처리 
		//@@ 									-> handler.nextState 채널로 ChaincodeMessage 송신 및 응답 처리
		//@@ 			수신된 Event 가 현재 State 에서 발생될 수 없는 것이면, 에러 처리
		//@@ 			handler.FSM 의 State 를 전이(transition)
		//@@ 		handler.nextState 채널에서 이벤트 발생 && Chaincode 로 응답을 보내줘야 한다면
		//@@ 		nsInfo.msg 을 handler.ChatStream 을 통해 전송
		//@@ select : ccchan, ccsupportchan, ipc.stopChan --> channel close
		ipc.launchInProc(ctxt, ccid.ChaincodeSpec.ChaincodeID.Name, args, env, ccSupport)
	}()

	return nil
}

//Stop stops a system codechain
//Stop함수는 시스템 체인코드를 정지시킴 (stopChan 채널로 빈 msg 전송)
//instRegistry (Map) 에서 Chaincode삭제
//@@ typeRegistry ( map[string]*inprocContainer ) 에 존재하는지 확인
//@@ instRegistry ( map[string]*inprocContainer ) 에 존재하는지 확인
//@@ inprocContainer 의 stopChan 로 빈 structure 전송
//@@ instRegistry ( map[string]*inprocContainer ) 에서 삭제
func (vm *InprocVM) Stop(ctxt context.Context, ccid ccintf.CCID, timeout uint, dontkill bool, dontremove bool) error {
	path := ccid.ChaincodeSpec.ChaincodeID.Path

	ipctemplate := typeRegistry[path]
	if ipctemplate == nil {
		return fmt.Errorf("%s not registered", path)
	}

	ipc := instRegistry[ccid.ChaincodeSpec.ChaincodeID.Name]

	if ipc == nil {
		return fmt.Errorf("%s not found", ccid.ChaincodeSpec.ChaincodeID.Name)
	}

	if !ipc.running {
		return fmt.Errorf("%s not running", ccid.ChaincodeSpec.ChaincodeID.Name)
	}

	ipc.stopChan <- struct{}{}

	delete(instRegistry, ccid.ChaincodeSpec.ChaincodeID.Name)
	//TODO stop
	return nil
}

//Destroy destroys an image
func (vm *InprocVM) Destroy(ctxt context.Context, ccid ccintf.CCID, force bool, noprune bool) error {
	//not implemented
	return nil
}

//GetVMName ignores the peer and network name as it just needs to be unique in process
//GetVMName함수는 프로세스 내에서 unique 해야 하므로 피어와 네트워크명을 무시함
func (vm *InprocVM) GetVMName(ccid ccintf.CCID) (string, error) {
	return ccid.ChaincodeSpec.ChaincodeID.Name, nil
}
