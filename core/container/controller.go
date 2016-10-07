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

package container

import (
	"fmt"
	"io"
	"sync"

	"golang.org/x/net/context"

	"github.com/hyperledger/fabric/core/container/ccintf"
	"github.com/hyperledger/fabric/core/container/dockercontroller"
	"github.com/hyperledger/fabric/core/container/inproccontroller"
)

//abstract virtual image for supporting arbitrary virual machines
//
// vm interface : 임의의 가상 머신을 지원하기 위한 가상 이미지 인터페이스
type vm interface {
	Deploy(ctxt context.Context, ccid ccintf.CCID, args []string, env []string, attachstdin bool, attachstdout bool, reader io.Reader) error
	Start(ctxt context.Context, ccid ccintf.CCID, args []string, env []string, attachstdin bool, attachstdout bool, reader io.Reader) error
	Stop(ctxt context.Context, ccid ccintf.CCID, timeout uint, dontkill bool, dontremove bool) error
	Destroy(ctxt context.Context, ccid ccintf.CCID, force bool, noprune bool) error
	GetVMName(ccID ccintf.CCID) (string, error)
}

type refCountedLock struct {
	refCount int
	lock     *sync.RWMutex
}

//VMController - manages VMs
//   . abstract construction of different types of VMs (we only care about Docker for now)
//   . manage lifecycle of VM (start with build, start, stop ...
//     eventually probably need fine grained management)
//
// VMController 구조체 : VM들을 관리
//   . VM 유형 생성(현재는 Docker만)
//   . VM lifecycle 관리( build, start, stop 등으로 시작해서 세밀한 관리가 필요함)
//   .
type VMController struct {
	sync.RWMutex
	// Handlers for each chaincode
	containerLocks map[string]*refCountedLock
}

//singleton...acess through NewVMController
//
//singleton 객체, NewVMController로 액세스함
var vmcontroller *VMController

//constants for supported containers
//
//지원되는 컨테이너용 상수
const (
	DOCKER = "Docker"
	SYSTEM = "System"
)

//NewVMController - creates/returns singleton
//
//NerVMController - singleton 객체를 생성하고 리턴
//singleton pattern : 여러차례 객체 생성이 호출되더라도 프로그램내에서는 하나의 객체만 생성해서 유지됨
func init() {
	vmcontroller = new(VMController)
	vmcontroller.containerLocks = make(map[string]*refCountedLock)
}

func (vmc *VMController) newVM(typ string) vm {
	var (
		v vm
	)

	switch typ {
	case DOCKER:
		v = &dockercontroller.DockerVM{}
	case SYSTEM:
		v = &inproccontroller.InprocVM{}
	default:
		v = &dockercontroller.DockerVM{}
	}
	return v
}

// 컨테이너를 sync.RWMutex lock 처리
func (vmc *VMController) lockContainer(id string) {
	//get the container lock under global lock
	//global lock 상태에서 컨테이너 lock을 획득
	vmcontroller.Lock()
	var refLck *refCountedLock
	var ok bool
	if refLck, ok = vmcontroller.containerLocks[id]; !ok {
		refLck = &refCountedLock{refCount: 1, lock: &sync.RWMutex{}}
		vmcontroller.containerLocks[id] = refLck
	} else {
		refLck.refCount++
		vmLogger.Debugf("refcount %d (%s)", refLck.refCount, id)
	}
	vmcontroller.Unlock()
	vmLogger.Debugf("waiting for container(%s) lock", id)
	refLck.lock.Lock()
	vmLogger.Debugf("got container (%s) lock", id)
}

// 컨테이너의 sync.RWMutex lock 해제(unlock)
func (vmc *VMController) unlockContainer(id string) {
	vmcontroller.Lock()
	if refLck, ok := vmcontroller.containerLocks[id]; ok {
		if refLck.refCount <= 0 {
			panic("refcnt <= 0")
		}
		refLck.lock.Unlock()
		if refLck.refCount--; refLck.refCount == 0 {
			vmLogger.Debugf("container lock deleted(%s)", id)
			delete(vmcontroller.containerLocks, id)
		}
	} else {
		vmLogger.Debugf("no lock to unlock(%s)!!", id)
	}
	vmcontroller.Unlock()
}

//VMCReqIntf - all requests should implement this interface.
//The context should be passed and tested at each layer till we stop
//note that we'd stop on the first method on the stack that does not
//take context
//
//VMCReqIntf interface : 모든 request 들은 이 인터페이스를 구현해야함
//context는 각각의 레이어 구간마다 테스트가 필요함
type VMCReqIntf interface {
	do(ctxt context.Context, v vm) VMCResp
	getCCID() ccintf.CCID
}

//VMCResp - response from requests. resp field is a anon interface.
//It can hold any response. err should be tested first
//
//VMCResp 구조체 : 요청에 대한 응답 구조체. Resp는 anon interface(anonymous)
//따라서 모든 응답을 처리할 수 있음. Err는 가장 먼저 테스트 되어야함.
type VMCResp struct {
	Err  error
	Resp interface{}
}

//CreateImageReq - properties for creating an container image
//
//CreateImageReq 구조체 : 컨테이너 이미지 생성을 위한 속성값 구조체
type CreateImageReq struct {
	ccintf.CCID
	Reader       io.Reader
	AttachStdin  bool
	AttachStdout bool
	Args         []string
	Env          []string
}

func (bp CreateImageReq) do(ctxt context.Context, v vm) VMCResp {
	var resp VMCResp

	if err := v.Deploy(ctxt, bp.CCID, bp.Args, bp.Env, bp.AttachStdin, bp.AttachStdout, bp.Reader); err != nil {
		resp = VMCResp{Err: err}
	} else {
		resp = VMCResp{}
	}

	return resp
}

func (bp CreateImageReq) getCCID() ccintf.CCID {
	return bp.CCID
}

//StartImageReq - properties for starting a container.
//StartImageReq 구조체 - 컨테이너 구동을 위한 속성값 구조체
type StartImageReq struct {
	ccintf.CCID
	Reader       io.Reader
	Args         []string
	Env          []string
	AttachStdin  bool
	AttachStdout bool
}

func (si StartImageReq) do(ctxt context.Context, v vm) VMCResp {
	var resp VMCResp

	if err := v.Start(ctxt, si.CCID, si.Args, si.Env, si.AttachStdin, si.AttachStdout, si.Reader); err != nil {
		resp = VMCResp{Err: err}
	} else {
		resp = VMCResp{}
	}

	return resp
}

func (si StartImageReq) getCCID() ccintf.CCID {
	return si.CCID
}

//StopImageReq - properties for stopping a container.
//StopImageReq 구조체 컨테이너 구동 정지를 위한 속성값 구조체
type StopImageReq struct {
	ccintf.CCID
	Timeout uint
	//by default we will kill the container after stopping
	//
	//default : 컨테이너 stop후 kill 처리
	Dontkill bool
	//by default we will remove the container after killing
	//
	//default : 컨테이너 kill후 remove 처리
	Dontremove bool
}

func (si StopImageReq) do(ctxt context.Context, v vm) VMCResp {
	var resp VMCResp

	if err := v.Stop(ctxt, si.CCID, si.Timeout, si.Dontkill, si.Dontremove); err != nil {
		resp = VMCResp{Err: err}
	} else {
		resp = VMCResp{}
	}

	return resp
}

func (si StopImageReq) getCCID() ccintf.CCID {
	return si.CCID
}

//DestroyImageReq - properties for stopping a container.
type DestroyImageReq struct {
	ccintf.CCID
	Timeout uint
	Force   bool
	NoPrune bool
}

func (di DestroyImageReq) do(ctxt context.Context, v vm) VMCResp {
	var resp VMCResp

	if err := v.Destroy(ctxt, di.CCID, di.Force, di.NoPrune); err != nil {
		resp = VMCResp{Err: err}
	} else {
		resp = VMCResp{}
	}

	return resp
}

func (di DestroyImageReq) getCCID() ccintf.CCID {
	return di.CCID
}

//VMCProcess should be used as follows
//   . construct a context
//   . construct req of the right type (e.g., CreateImageReq)
//   . call it in a go routine
//   . process response in the go routing
//context can be cancelled. VMCProcess will try to cancel calling functions if it can
//For instance docker clients api's such as BuildImage are not cancelable.
//In all cases VMCProcess will wait for the called go routine to return
//
//VMCProcess함수는 아래와 같이 사용되어야 함
//   . context 생성
//   . 유형별 req(컨테이너 컨트롤 속성 구조체) 생성 (e.g. CreateImageReq)
//   . 고루틴 내에서 호출
//   . 고루틴 내에서 응답 처리
//context는 취소 가능함. VMCProcess는 함수 호출 취소 시도 가능.
//예를들어 도커 클라이언트 API의 BuildImage 같은 명령은 취소 불가함
//VMCProcess는 호출된 고루틴의 리턴을 항상 대기하고 있음
//  KTODO : 체인코드 실행시 VMCProcess()로 VM 이미지를 콘트롤함, chaincode쪽 분석시 추가 연계 분석필요!
//  KTODO : 필요하면 아래 flow 그림으로 그릴것
//  Chaincode(peer) deploy/invoke -> VMCProcess(Create/start/stop/destroy vm)	-> newVM(SYSTEM)-inproccontroller -> req.do() -> 채널
//																	  	-> newVM(DOCKER)-dockercontroller -> req.do()
//  @param ctxt context.Context : CCHANDLER를 키값으로 context 할당, peer의 체인코드와의 인터페이스 설정
//  @param vmtype : 체인코드 deploy시 설정한 값, 현재는 Docker/System 두가지 값을 가짐
//  @param req : container 패키지의 CreateImageReq,StartImageReq,StopImageReq,DestroyImageReq 중 택1
func VMCProcess(ctxt context.Context, vmtype string, req VMCReqIntf) (interface{}, error) {
	v := vmcontroller.newVM(vmtype)

	if v == nil {
		return nil, fmt.Errorf("Unknown VM type %s", vmtype)
	}

	c := make(chan struct{})
	var resp interface{}
	go func() {
		defer close(c)

		id, err := v.GetVMName(req.getCCID())
		if err != nil {
			resp = VMCResp{Err: err}
			return
		}
		vmcontroller.lockContainer(id)
		resp = req.do(ctxt, v)
		vmcontroller.unlockContainer(id)
	}()

	select {
	case <-c:
		return resp, nil
	case <-ctxt.Done():
		//TODO cancel req.do ... (needed) ?
		<-c
		return nil, ctxt.Err()
	}
}
