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

package chaincode

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	logging "github.com/op/go-logging"
	"github.com/spf13/viper"
	"golang.org/x/net/context"

	"strings"

	"github.com/hyperledger/fabric/core/container"
	"github.com/hyperledger/fabric/core/container/ccintf"
	"github.com/hyperledger/fabric/core/crypto"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/flogging"
	pb "github.com/hyperledger/fabric/protos"
)

// ChainName is the name of the chain to which this chaincode support belongs to.
// @@ chaincode support가 속한 체인의 이름.
type ChainName string

const (
	// DefaultChain is the name of the default chain.
	DefaultChain ChainName = "default"
	// DevModeUserRunsChaincode property allows user to run chaincode in development environment
	DevModeUserRunsChaincode       string = "dev"
	chaincodeStartupTimeoutDefault int    = 5000
	chaincodeInstallPathDefault    string = "/opt/gopath/bin/"
	peerAddressDefault             string = "0.0.0.0:7051"
)

// chains is a map between different blockchains and their ChaincodeSupport.
//this needs to be a first class, top-level object... for now, lets just have a placeholder
// @@ chains : 서로 다른 블록체인과  그들의 ChaincodeSupport간의 map, 가장 상위 레벨의 객체.
var chains map[ChainName]*ChaincodeSupport

func init() {
	chains = make(map[ChainName]*ChaincodeSupport)
}

//chaincode runtime environment encapsulates handler and container environment
//This is where the VM that's running the chaincode would hook in
// @@ 체인코드 실행 환경은 핸들러와 컨테이너 환경을 캡슐화한 것.
// @@ 체인코드를 실행하는 vm에 필요.
type chaincodeRTEnv struct {
	handler *Handler
}

// runningChaincodes contains maps of chaincodeIDs to their chaincodeRTEs
// @@ chaincodeID와 chaincodeRTE(실행 환경)을 매핑한 것을 가지고 있음
type runningChaincodes struct {
	sync.RWMutex
	// chaincode environment for each chaincode
	chaincodeMap map[string]*chaincodeRTEnv
}

// GetChain returns the chaincode support for a given chain
// @@ 입력인자로 주어진 chain의 chaincode support를 리턴
func GetChain(name ChainName) *ChaincodeSupport {
	return chains[name]
}

//call this under lock
//@@ readyNotify 채널을 가진 chaincodeRTEnv 생성 --> chaincodeSupport 에 등록 --> 채널 리턴
func (chaincodeSupport *ChaincodeSupport) preLaunchSetup(chaincode string) chan bool {
	//register placeholder Handler. This will be transferred in registerHandler
	//NOTE: from this point, existence of handler for this chaincode means the chaincode
	//is in the process of getting started (or has been started)
	// @@ register 핸들러로 대체?
	notfy := make(chan bool, 1)
	chaincodeSupport.runningChaincodes.chaincodeMap[chaincode] = &chaincodeRTEnv{handler: &Handler{readyNotify: notfy}}
	return notfy
}

//call this under lock
//@@ ChaincodeID 로 *chaincodeRTEnv 찾아서 리턴
func (chaincodeSupport *ChaincodeSupport) chaincodeHasBeenLaunched(chaincode string) (*chaincodeRTEnv, bool) {
	chrte, hasbeenlaunched := chaincodeSupport.runningChaincodes.chaincodeMap[chaincode]
	return chrte, hasbeenlaunched
}

// NewChaincodeSupport creates a new ChaincodeSupport instance
// @@ ChaincodeSupport 객체를 생성
func NewChaincodeSupport(chainname ChainName, getPeerEndpoint func() (*pb.PeerEndpoint, error), userrunsCC bool, ccstartuptimeout time.Duration, secHelper crypto.Peer) *ChaincodeSupport {
	pnid := viper.GetString("peer.networkId")
	pid := viper.GetString("peer.id")

	s := &ChaincodeSupport{name: chainname, runningChaincodes: &runningChaincodes{chaincodeMap: make(map[string]*chaincodeRTEnv)}, secHelper: secHelper, peerNetworkID: pnid, peerID: pid}

	//initialize global chain
	// 체인을 초기화
	chains[chainname] = s

	peerEndpoint, err := getPeerEndpoint()
	if err != nil {
		chaincodeLogger.Errorf("Error getting PeerEndpoint, using peer.address: %s", err)
		s.peerAddress = viper.GetString("peer.address")
	} else {
		s.peerAddress = peerEndpoint.Address
	}
	chaincodeLogger.Infof("Chaincode support using peerAddress: %s\n", s.peerAddress)
	//peerAddress = viper.GetString("peer.address")
	if s.peerAddress == "" {
		s.peerAddress = peerAddressDefault
	}

	s.userRunsCC = userrunsCC

	s.ccStartupTimeout = ccstartuptimeout

	//TODO I'm not sure if this needs to be on a per chain basis... too lowel and just needs to be a global default ?
	s.chaincodeInstallPath = viper.GetString("chaincode.installpath")
	if s.chaincodeInstallPath == "" {
		s.chaincodeInstallPath = chaincodeInstallPathDefault
	}

	s.peerTLS = viper.GetBool("peer.tls.enabled")
	if s.peerTLS {
		s.peerTLSCertFile = viper.GetString("peer.tls.cert.file")
		s.peerTLSKeyFile = viper.GetString("peer.tls.key.file")
		s.peerTLSSvrHostOrd = viper.GetString("peer.tls.serverhostoverride")
	}

	kadef := 0
	if ka := viper.GetString("chaincode.keepalive"); ka == "" {
		s.keepalive = time.Duration(kadef) * time.Second
	} else {
		t, terr := strconv.Atoi(ka)
		if terr != nil {
			chaincodeLogger.Errorf("Invalid keepalive value %s (%s) defaulting to %d", ka, terr, kadef)
			t = kadef
		} else if t <= 0 {
			chaincodeLogger.Debugf("Turn off keepalive(value %s)", ka)
			t = kadef
		}
		s.keepalive = time.Duration(t) * time.Second
	}

	viper.SetEnvPrefix("CORE")
	viper.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)

	chaincodeLogLevelString := viper.GetString("logging.chaincode")
	chaincodeLogLevel, err := logging.LogLevel(chaincodeLogLevelString)

	if err == nil {
		s.chaincodeLogLevel = chaincodeLogLevel.String()
	} else {
		chaincodeLogger.Infof("chaincode logging level %s is invalid. defaulting to %s\n", chaincodeLogLevelString, flogging.DefaultLoggingLevel().String())
		s.chaincodeLogLevel = flogging.DefaultLoggingLevel().String()
	}

	return s
}

// // ChaincodeStream standard stream for ChaincodeMessage type.
// type ChaincodeStream interface {
// 	Send(*pb.ChaincodeMessage) error
// 	Recv() (*pb.ChaincodeMessage, error)
// }

// ChaincodeSupport responsible for providing interfacing with chaincodes from the Peer.
// @@ ChaincodeSupport : 피어에서 체인코드와의 인터페이싱을 책임지는 객체
type ChaincodeSupport struct {
	name                 ChainName
	runningChaincodes    *runningChaincodes
	peerAddress          string
	ccStartupTimeout     time.Duration
	chaincodeInstallPath string
	userRunsCC           bool
	secHelper            crypto.Peer
	peerNetworkID        string
	peerID               string
	peerTLS              bool
	peerTLSCertFile      string
	peerTLSKeyFile       string
	peerTLSSvrHostOrd    string
	keepalive            time.Duration
	chaincodeLogLevel    string
}

// DuplicateChaincodeHandlerError returned if attempt to register same chaincodeID while a stream already exists.
type DuplicateChaincodeHandlerError struct {
	ChaincodeID *pb.ChaincodeID
}

func (d *DuplicateChaincodeHandlerError) Error() string {
	return fmt.Sprintf("Duplicate chaincodeID error: %s", d.ChaincodeID)
}

func newDuplicateChaincodeHandlerError(chaincodeHandler *Handler) error {
	return &DuplicateChaincodeHandlerError{ChaincodeID: chaincodeHandler.ChaincodeID}
}

//@@ chaincode 에 대한 handler 등록
func (chaincodeSupport *ChaincodeSupport) registerHandler(chaincodehandler *Handler) error {
	key := chaincodehandler.ChaincodeID.Name

	chaincodeSupport.runningChaincodes.Lock()
	defer chaincodeSupport.runningChaincodes.Unlock()

	//@@ ChaincodeID 로 *chaincodeRTEnv 를 찾으면 에러 처리
	chrte2, ok := chaincodeSupport.chaincodeHasBeenLaunched(key)
	if ok && chrte2.handler.registered == true {
		chaincodeLogger.Debugf("duplicate registered handler(key:%s) return error", key)
		// Duplicate, return error
		return newDuplicateChaincodeHandlerError(chaincodehandler)
	}
	//a placeholder, unregistered handler will be setup by query or transaction processing that comes
	//through via consensus. In this case we swap the handler and give it the notify channel
	//@@ chaincode 있는 경우 : chaincodehandler 를 handler 로 등록
	//@@ chaincode 없는 경우 : runningChaincodes Map 에 insert
	if chrte2 != nil {
		chaincodehandler.readyNotify = chrte2.handler.readyNotify
		chrte2.handler = chaincodehandler
	} else {
		chaincodeSupport.runningChaincodes.chaincodeMap[key] = &chaincodeRTEnv{handler: chaincodehandler}
	}

	//@@ 등록 상태 변경
	chaincodehandler.registered = true

	//now we are ready to receive messages and send back responses
	chaincodehandler.txCtxs = make(map[string]*transactionContext)
	chaincodehandler.txidMap = make(map[string]bool)
	chaincodehandler.isTransaction = make(map[string]bool)

	chaincodeLogger.Debugf("registered handler complete for chaincode %s", key)

	return nil
}

// 체인코드 핸들러를 등록 해제
func (chaincodeSupport *ChaincodeSupport) deregisterHandler(chaincodehandler *Handler) error {

	// clean up rangeQueryIteratorMap
	for _, context := range chaincodehandler.txCtxs {
		for _, v := range context.rangeQueryIteratorMap {
			v.Close()
		}
	}

	key := chaincodehandler.ChaincodeID.Name
	chaincodeLogger.Debugf("Deregister handler: %s", key)
	chaincodeSupport.runningChaincodes.Lock()
	defer chaincodeSupport.runningChaincodes.Unlock()
	//@@ ChaincodeID 로 *chaincodeRTEnv 를 찾지못하면 에러 처리
	if _, ok := chaincodeSupport.chaincodeHasBeenLaunched(key); !ok {
		// Handler NOT found
		return fmt.Errorf("Error deregistering handler, could not find handler with key: %s", key)
	}
	delete(chaincodeSupport.runningChaincodes.chaincodeMap, key)
	chaincodeLogger.Debugf("Deregistered handler with key: %s", key)
	return nil
}

// Based on state of chaincode send either init or ready to move to ready state
// @@ 체인코드의 상태에 따라 init 또는 ready를 송신하여 ready 상태로 전환.
//@@ handler 가 등록되어 있지 않다면 에러!! (실행되지 않았다는 것과 동치임)
//@@ transactionContext 생성, ChaincodeMessage 생성 (SecurityContext 처리 포함)
//@@ handler.nextState 채널로 ChaincodeMessage 전송 & responseNotifier 생성
//@@ 응답수신 대기 && 에러응답 처리
//@@ handler.txCtxs (map[string]*transactionContext) 에서 txid 삭제
func (chaincodeSupport *ChaincodeSupport) sendInitOrReady(context context.Context, txid string, chaincode string, initArgs [][]byte, timeout time.Duration, tx *pb.Transaction, depTx *pb.Transaction) error {
	chaincodeSupport.runningChaincodes.Lock()
	//if its in the map, there must be a connected stream...nothing to do
	var chrte *chaincodeRTEnv
	var ok bool
	//@@ ChaincodeID 로 *chaincodeRTEnv 를 찾지 못하면 에러 처리
	if chrte, ok = chaincodeSupport.chaincodeHasBeenLaunched(chaincode); !ok {
		chaincodeSupport.runningChaincodes.Unlock()
		chaincodeLogger.Debugf("handler not found for chaincode %s", chaincode)
		return fmt.Errorf("handler not found for chaincode %s", chaincode)
	}
	chaincodeSupport.runningChaincodes.Unlock()

	var notfy chan *pb.ChaincodeMessage
	var err error
	//@@ transactionContext 생성, ChaincodeMessage 생성 (SecurityContext 처리 포함)
	//@@ handler.nextState 채널로 ChaincodeMessage 전송 & responseNotifier 생성
	if notfy, err = chrte.handler.initOrReady(txid, initArgs, tx, depTx); err != nil {
		return fmt.Errorf("Error sending %s: %s", pb.ChaincodeMessage_INIT, err)
	}
	//@@ 응답수신 대기 && 에러응답 처리
	if notfy != nil {
		select {
		case ccMsg := <-notfy:
			if ccMsg.Type == pb.ChaincodeMessage_ERROR {
				err = fmt.Errorf("Error initializing container %s: %s", chaincode, string(ccMsg.Payload))
			}
		case <-time.After(timeout):
			err = fmt.Errorf("Timeout expired while executing send init message")
		}
	}

	//if initOrReady succeeded, our responsibility to delete the context
	//@@ handler.txCtxs (map[string]*transactionContext) 에서 txid 삭제
	chrte.handler.deleteTxContext(txid)

	return err
}

//get args and env given chaincodeID
// @@ 입력된 chaincodeID에 속하는 arguments와 환경 변수를 get
//@@ args 에는 Path, ChaincodeName, peer.address 만 있음
func (chaincodeSupport *ChaincodeSupport) getArgsAndEnv(cID *pb.ChaincodeID, cLang pb.ChaincodeSpec_Type) (args []string, envs []string, err error) {
	envs = []string{"CORE_CHAINCODE_ID_NAME=" + cID.Name}
	//if TLS is enabled, pass TLS material to chaincode
	if chaincodeSupport.peerTLS {
		envs = append(envs, "CORE_PEER_TLS_ENABLED=true")
		envs = append(envs, "CORE_PEER_TLS_CERT_FILE="+chaincodeSupport.peerTLSCertFile)
		if chaincodeSupport.peerTLSSvrHostOrd != "" {
			envs = append(envs, "CORE_PEER_TLS_SERVERHOSTOVERRIDE="+chaincodeSupport.peerTLSSvrHostOrd)
		}
	} else {
		envs = append(envs, "CORE_PEER_TLS_ENABLED=false")
	}

	if chaincodeSupport.chaincodeLogLevel != "" {
		envs = append(envs, "CORE_LOGGING_CHAINCODE="+chaincodeSupport.chaincodeLogLevel)
	}

	switch cLang {
	case pb.ChaincodeSpec_GOLANG, pb.ChaincodeSpec_CAR:
		//chaincode executable will be same as the name of the chaincode
		args = []string{chaincodeSupport.chaincodeInstallPath + cID.Name, fmt.Sprintf("-peer.address=%s", chaincodeSupport.peerAddress)}
		chaincodeLogger.Debugf("Executable is %s", args[0])
	case pb.ChaincodeSpec_JAVA:
		//TODO add security args
		args = strings.Split(
			fmt.Sprintf("java -jar chaincode.jar -a %s -i %s",
				chaincodeSupport.peerAddress, cID.Name),
			" ")
		if chaincodeSupport.peerTLS {
			args = append(args, " -s")
		}
		chaincodeLogger.Debugf("Executable is %s", args[0])
	default:
		return nil, nil, fmt.Errorf("Unknown chaincodeType: %s", cLang)
	}
	return args, envs, nil
}

// launchAndWaitForRegister will launch container if not already running. Use the targz to create the image if not found
//@@ 이미 실행되었다면 return true, nil
//@@ chaincodeSupport 에 readyNotify 채널을 가진 chaincodeRTEnv 생성/등록
//@@ container.StartImageReq 생성후 VMCProcesS() 실행 ( 내부 : vm.Start() )
//@@ readyNotify 채널에서 true 가 오면 정상, false 가 오면 실패
//@@ 에러처리 : chaincodeSupport.Stop() (vm.Stop() 실행 (에러 체크 X) && runningChaincodes 에서 삭제)
func (chaincodeSupport *ChaincodeSupport) launchAndWaitForRegister(ctxt context.Context, cds *pb.ChaincodeDeploymentSpec, cID *pb.ChaincodeID, txid string, cLang pb.ChaincodeSpec_Type, targz io.Reader) (bool, error) {
	chaincode := cID.Name
	if chaincode == "" {
		return false, fmt.Errorf("chaincode name not set")
	}

	chaincodeSupport.runningChaincodes.Lock()
	var ok bool
	//if its in the map, there must be a connected stream...nothing to do
	//@@ ChaincodeID 로 *chaincodeRTEnv 를 찾으면 return true, nil
	if _, ok = chaincodeSupport.chaincodeHasBeenLaunched(chaincode); ok {
		chaincodeLogger.Debugf("chaincode is running and ready: %s", chaincode)
		chaincodeSupport.runningChaincodes.Unlock()
		return true, nil
	}
	alreadyRunning := false

	//@@ readyNotify 채널을 가진 chaincodeRTEnv 생성 --> chaincodeSupport 에 등록 --> 채널 리턴
	notfy := chaincodeSupport.preLaunchSetup(chaincode)
	chaincodeSupport.runningChaincodes.Unlock()

	//launch the chaincode

	// @@ 입력된 chaincodeID에 속하는 arguments와 환경 변수를 get
	//@@ args 에는 Path, ChaincodeName, peer.address 만 있음
	args, env, err := chaincodeSupport.getArgsAndEnv(cID, cLang)
	if err != nil {
		return alreadyRunning, err
	}

	chaincodeLogger.Debugf("start container: %s(networkid:%s,peerid:%s)", chaincode, chaincodeSupport.peerNetworkID, chaincodeSupport.peerID)
	// @@체인코드가 유저 체인코드인지, 시스템 체인코드인지 구분하여 VM호출하기 위함.
	vmtype, _ := chaincodeSupport.getVMType(cds)
	// @@컨테이너 패키지의 ccinf(체인코드인터페이스)를 통해 이미지 생성
	sir := container.StartImageReq{CCID: ccintf.CCID{ChaincodeSpec: cds.ChaincodeSpec, NetworkID: chaincodeSupport.peerNetworkID, PeerID: chaincodeSupport.peerID}, Reader: targz, Args: args, Env: env}

	ipcCtxt := context.WithValue(ctxt, ccintf.GetCCHandlerKey(), chaincodeSupport)
	// @@컨테이너 패키지의 의 VMCprocess를 호출하여 컨테이너 실행
	//@@ vm.Start() 실행 : 사전에 생성한 docker image로 컨테이너를 구동시킴.
	resp, err := container.VMCProcess(ipcCtxt, vmtype, sir)
	if err != nil || (resp != nil && resp.(container.VMCResp).Err != nil) {
		if err == nil {
			err = resp.(container.VMCResp).Err
		}
		err = fmt.Errorf("Error starting container: %s", err)
		chaincodeSupport.runningChaincodes.Lock()
		delete(chaincodeSupport.runningChaincodes.chaincodeMap, chaincode)
		chaincodeSupport.runningChaincodes.Unlock()
		return alreadyRunning, err
	}

	//wait for REGISTER state
	// @@ REGISTER 상태를 대기
	select {
	case ok := <-notfy: // @@ 성공시 noti
		if !ok {
			err = fmt.Errorf("registration failed for %s(networkid:%s,peerid:%s,tx:%s)", chaincode, chaincodeSupport.peerNetworkID, chaincodeSupport.peerID, txid)
		}
	// @@ 등록에 대한 timeout 발생
	case <-time.After(chaincodeSupport.ccStartupTimeout):
		err = fmt.Errorf("Timeout expired while starting chaincode %s(networkid:%s,peerid:%s,tx:%s)", chaincode, chaincodeSupport.peerNetworkID, chaincodeSupport.peerID, txid)
	}
	if err != nil {
		chaincodeLogger.Debugf("stopping due to error while launching %s", err)
		// @@ vm.Stop() 실행 (에러 체크 X) && runningChaincodes 에서 삭제
		errIgnore := chaincodeSupport.Stop(ctxt, cds)
		if errIgnore != nil {
			chaincodeLogger.Debugf("error on stop %s(%s)", errIgnore, err)
		}
	}
	return alreadyRunning, err
}

//Stop stops a chaincode if running
// @@ vm.Stop() 실행 (에러 체크 X) && runningChaincodes 에서 삭제
func (chaincodeSupport *ChaincodeSupport) Stop(context context.Context, cds *pb.ChaincodeDeploymentSpec) error {
	chaincode := cds.ChaincodeSpec.ChaincodeID.Name
	if chaincode == "" {
		return fmt.Errorf("chaincode name not set")
	}

	//stop the chaincode
	sir := container.StopImageReq{CCID: ccintf.CCID{ChaincodeSpec: cds.ChaincodeSpec, NetworkID: chaincodeSupport.peerNetworkID, PeerID: chaincodeSupport.peerID}, Timeout: 0}

	vmtype, _ := chaincodeSupport.getVMType(cds)

	// StopImageReq 이므로, 내부적으로 vm.Stop() 실행
	_, err := container.VMCProcess(context, vmtype, sir)
	if err != nil {
		err = fmt.Errorf("Error stopping container: %s", err)
		//but proceed to cleanup
	}

	chaincodeSupport.runningChaincodes.Lock()
	//@@ ChaincodeID 로 *chaincodeRTEnv 를 찾지 못하면 그냥 리턴
	if _, ok := chaincodeSupport.chaincodeHasBeenLaunched(chaincode); !ok {
		//nothing to do
		chaincodeSupport.runningChaincodes.Unlock()
		return nil
	}

	delete(chaincodeSupport.runningChaincodes.chaincodeMap, chaincode)

	chaincodeSupport.runningChaincodes.Unlock()

	return err
}

// Launch will launch the chaincode if not running (if running return nil) and will wait for handler of the chaincode to get into FSM ready state.
// @@ Lanunch : 체인코드가 현재 실행중이 아니라면 실행시키고, 체인코드의 핸들러가 FSM의 ready 상태가 될 때까지 wait
//@@ Ledger 객체 생성 ( Ledger = ledger.blockchain + state.State + currentID )
//@@ ChaincodeID 로 Tx 검색 ( Deploy 일 때는, ChaincodeID == TxID 인 것 같네?? )
//@@ 컨테이너가 시스템 체인코드 컨테이거나, dev 모드라면 컨테이너를 실행시킨다.
//@@ ChaincodeSupport : 피어에서 체인코드와의 인터페이싱을 책임지는 객체
//@@-----------------------------------------------------------------------------------------
//@@ launchAndWaitForRegister() 실행
//@@ 이미 실행되었다면 return true, nil
//@@ chaincodeSupport 에 readyNotify 채널을 가진 chaincodeRTEnv 생성/등록
//@@ container.StartImageReq 생성후 VMCProcesS() 실행 ( 내부 : vm.Start() )
//@@ readyNotify 채널에서 true 가 오면 정상, false 가 오면 실패
//@@ 에러처리 : chaincodeSupport.Stop() (vm.Stop() 실행 (에러 체크 X) && runningChaincodes 에서 삭제)
//@@-----------------------------------------------------------------------------------------
//@@ sendInitOrReady() 실행
//@@ handler 가 등록되어 있지 않다면 에러!! (실행되지 않았다는 것과 동치임)
//@@ transactionContext 생성, ChaincodeMessage 생성 (SecurityContext 처리 포함)
//@@ handler.nextState 채널로 ChaincodeMessage 전송 & responseNotifier 생성
//@@ 응답수신 대기 && 에러응답 처리
//@@ handler.txCtxs (map[string]*transactionContext) 에서 txid 삭제
//@@-----------------------------------------------------------------------------------------
//@@ ChaincodeID, CtorMsg, err 리턴
func (chaincodeSupport *ChaincodeSupport) Launch(context context.Context, t *pb.Transaction) (*pb.ChaincodeID, *pb.ChaincodeInput, error) {
	//build the chaincode
	var cID *pb.ChaincodeID
	var cMsg *pb.ChaincodeInput
	var cLang pb.ChaincodeSpec_Type
	var initargs [][]byte

	//@@ Transaction -> ChaincodeDeploymentSpec 생성
	cds := &pb.ChaincodeDeploymentSpec{}
	//@@ Tx 가 Deploy : ChaincodeID, CtorMsg, Lang, Args 추출
	if t.Type == pb.Transaction_CHAINCODE_DEPLOY {
		err := proto.Unmarshal(t.Payload, cds)
		if err != nil {
			return nil, nil, err
		}
		cID = cds.ChaincodeSpec.ChaincodeID
		cMsg = cds.ChaincodeSpec.CtorMsg
		cLang = cds.ChaincodeSpec.Type
		initargs = cMsg.Args
	//@@ Tx 가 Invoke / Query : ChaincodeID, CtorMsg 추출
	} else if t.Type == pb.Transaction_CHAINCODE_INVOKE || t.Type == pb.Transaction_CHAINCODE_QUERY {
		ci := &pb.ChaincodeInvocationSpec{}
		err := proto.Unmarshal(t.Payload, ci)
		if err != nil {
			return nil, nil, err
		}
		cID = ci.ChaincodeSpec.ChaincodeID
		cMsg = ci.ChaincodeSpec.CtorMsg
	} else {
		chaincodeSupport.runningChaincodes.Unlock()
		return nil, nil, fmt.Errorf("invalid transaction type: %d", t.Type)
	}
	chaincode := cID.Name
	chaincodeSupport.runningChaincodes.Lock()
	var chrte *chaincodeRTEnv
	var ok bool
	var err error
	//if its in the map, there must be a connected stream...nothing to do
	//@@ ChaincodeID 로 *chaincodeRTEnv 를 찾을 수 있는 경우 처리
	if chrte, ok = chaincodeSupport.chaincodeHasBeenLaunched(chaincode); ok {
		//@@ handler 가 등록되어 있다면 에러 (Dup)
		if !chrte.handler.registered {
			chaincodeSupport.runningChaincodes.Unlock()
			chaincodeLogger.Debugf("premature execution - chaincode (%s) is being launched", chaincode)
			err = fmt.Errorf("premature execution - chaincode (%s) is being launched", chaincode)
			return cID, cMsg, err
		}
		//@@ handler 가 실행되고 있다면 에러
		if chrte.handler.isRunning() {
			chaincodeLogger.Debugf("chaincode is running(no need to launch) : %s", chaincode)
			chaincodeSupport.runningChaincodes.Unlock()
			return cID, cMsg, nil
		}
		chaincodeLogger.Debugf("Container not in READY state(%s)...send init/ready", chrte.handler.FSM.Current())
	}
	chaincodeSupport.runningChaincodes.Unlock()

	var depTx *pb.Transaction

	//extract depTx so we can initialize hander.deployTXSecContext
	//we need it only after container is launched and only if this is not a deploy tx
	//NOTE: ideally this section should be moved before just before sendInitOrReady where
	//      where we need depTx.  However, as we don't check for ExecuteTransactions failure
	//      in consensus/helper, the following race is not resolved:
	//         1) deploy creates image
	//         2) query launches chaincode
	//         3) deploy returns "premature execution" error
	//         4) error ignored and deploy committed
	//         5) query successfully retrives committed tx and calls sendInitOrReady
	// See issue #710

	//@@ Tx 가 Deploy
	if t.Type != pb.Transaction_CHAINCODE_DEPLOY {
		//@@ Ledger 객체 생성 ( Ledger = ledger.blockchain + state.State + currentID )
		ledger, ledgerErr := ledger.GetLedger()

		if chaincodeSupport.userRunsCC {
			chaincodeLogger.Error("You are attempting to perform an action other than Deploy on Chaincode that is not ready and you are in developer mode. Did you forget to Deploy your chaincode?")
		}

		if ledgerErr != nil {
			return cID, cMsg, fmt.Errorf("Failed to get handle to ledger (%s)", ledgerErr)
		}

		//hopefully we are restarting from existing image and the deployed transaction exists
		//@@ ChaincodeID 로 Tx 검색 ( Deploy 일 때는, ChaincodeID == TxID 인 것 같네?? )
		depTx, ledgerErr = ledger.GetTransactionByID(chaincode)
		if ledgerErr != nil {
			return cID, cMsg, fmt.Errorf("Could not get deployment transaction for %s - %s", chaincode, ledgerErr)
		}
		if depTx == nil {
			return cID, cMsg, fmt.Errorf("deployment transaction does not exist for %s", chaincode)
		}
		if nil != chaincodeSupport.secHelper {
			var err error
			//@@ 현재 미구현임 : nill, error 리턴
			depTx, err = chaincodeSupport.secHelper.TransactionPreExecution(depTx)
			// Note that t is now decrypted and is a deep clone of the original input t
			if nil != err {
				return cID, cMsg, fmt.Errorf("failed tx preexecution%s - %s", chaincode, err)
			}
		}
		//Get lang from original deployment
		err := proto.Unmarshal(depTx.Payload, cds)
		if err != nil {
			return cID, cMsg, fmt.Errorf("failed to unmarshal deployment transactions for %s - %s", chaincode, err)
		}
		cLang = cds.ChaincodeSpec.Type
	}

	//from here on : if we launch the container and get an error, we need to stop the container

	//launch container if it is a System container or not in dev mode
	// 컨테이너가 시스템 체인코드 컨테이거나, dev 모드라면 컨테이너를 실행시킨다.
	//@@ ChaincodeSupport : 피어에서 체인코드와의 인터페이싱을 책임지는 객체
	if (!chaincodeSupport.userRunsCC || cds.ExecEnv == pb.ChaincodeDeploymentSpec_SYSTEM) && (chrte == nil || chrte.handler == nil) {
		var targz io.Reader = bytes.NewBuffer(cds.CodePackage)
		//@@ 이미 실행되었다면 return true, nil
		//@@ chaincodeSupport 에 readyNotify 채널을 가진 chaincodeRTEnv 생성/등록
		//@@ container.StartImageReq 생성후 VMCProcesS() 실행 ( 내부 : vm.Start() )
		//@@ readyNotify 채널에서 true 가 오면 정상, false 가 오면 실패
		//@@ 에러처리 : chaincodeSupport.Stop() (vm.Stop() 실행 (에러 체크 X) && runningChaincodes 에서 삭제)
		_, err = chaincodeSupport.launchAndWaitForRegister(context, cds, cID, t.Txid, cLang, targz)
		if err != nil {
			chaincodeLogger.Errorf("launchAndWaitForRegister failed %s", err)
			return cID, cMsg, err
		}
	}

	if err == nil {
		//send init (if (args)) and wait for ready state
		//@@ handler 가 등록되어 있지 않다면 에러!! (실행되지 않았다는 것과 동치임)
		//@@ transactionContext 생성, ChaincodeMessage 생성 (SecurityContext 처리 포함)
		//@@ handler.nextState 채널로 ChaincodeMessage 전송 & responseNotifier 생성
		//@@ 응답수신 대기 && 에러응답 처리
		//@@ handler.txCtxs (map[string]*transactionContext) 에서 txid 삭제
		err = chaincodeSupport.sendInitOrReady(context, t.Txid, chaincode, initargs, chaincodeSupport.ccStartupTimeout, t, depTx)
		if err != nil {
			chaincodeLogger.Errorf("sending init failed(%s)", err)
			err = fmt.Errorf("Failed to init chaincode(%s)", err)
			errIgnore := chaincodeSupport.Stop(context, cds)
			if errIgnore != nil {
				chaincodeLogger.Errorf("stop failed %s(%s)", errIgnore, err)
			}
		}
		chaincodeLogger.Debug("sending init completed")
	}

	chaincodeLogger.Debug("LaunchChaincode complete")

	//@@ ChaincodeID, CtorMsg, err 리턴
	return cID, cMsg, err
}

// getSecHelper returns the security help set from NewChaincodeSupport
func (chaincodeSupport *ChaincodeSupport) getSecHelper() crypto.Peer {
	return chaincodeSupport.secHelper
}

//getVMType - just returns a string for now. Another possibility is to use a factory method to
//return a VM executor
// @@ 체인코드가 실행될 vm 컨테이너를 리턴. 시스템일 경우는 시스템, 유저일 경우 docker.
func (chaincodeSupport *ChaincodeSupport) getVMType(cds *pb.ChaincodeDeploymentSpec) (string, error) {
	if cds.ExecEnv == pb.ChaincodeDeploymentSpec_SYSTEM {
		return container.SYSTEM, nil
	}
	return container.DOCKER, nil
}

// Deploy deploys the chaincode if not in development mode where user is running the chaincode.
// @@ 체인코드 deploy
//@@ ChaincodeDeploymentSpec 생성 ( Tx.Payload -> cds )
//@@ ChaincodeID 로 *chaincodeRTEnv 찾아서 있으면 에러
//@@ 입력된 chaincodeID에 속하는 arguments와 환경 변수를 get
//@@ (args 에는 Path, ChaincodeName, peer.address 만 있음)
//@@ CreateImageReq 생성 ( tar.gz 파일 형식 )
//@@ VMCProcess() 호출 : 내부에서 vm.Deploy() 실행
func (chaincodeSupport *ChaincodeSupport) Deploy(context context.Context, t *pb.Transaction) (*pb.ChaincodeDeploymentSpec, error) {
	//build the chaincode
	//@@ ChaincodeDeploymentSpec 생성 ( Tx.Payload -> cds )
	cds := &pb.ChaincodeDeploymentSpec{}
	err := proto.Unmarshal(t.Payload, cds)
	if err != nil {
		return nil, err
	}
	cID := cds.ChaincodeSpec.ChaincodeID
	cLang := cds.ChaincodeSpec.Type
	chaincode := cID.Name
	if err != nil {
		return cds, err
	}

	if chaincodeSupport.userRunsCC {
		chaincodeLogger.Debug("user runs chaincode, not deploying chaincode")
		return nil, nil
	}

	chaincodeSupport.runningChaincodes.Lock()
	//if its in the map, there must be a connected stream...and we are trying to build the code ?!
	//@@ ChaincodeID 로 *chaincodeRTEnv 를 찾으면 에러 처리
	if _, ok := chaincodeSupport.chaincodeHasBeenLaunched(chaincode); ok {
		chaincodeLogger.Debugf("deploy ?!! there's a chaincode with that name running: %s", chaincode)
		chaincodeSupport.runningChaincodes.Unlock()
		return cds, fmt.Errorf("deploy attempted but a chaincode with same name running %s", chaincode)
	}
	chaincodeSupport.runningChaincodes.Unlock()

	// @@ 입력된 chaincodeID에 속하는 arguments와 환경 변수를 get
	//@@ args 에는 Path, ChaincodeName, peer.address 만 있음
	args, envs, err := chaincodeSupport.getArgsAndEnv(cID, cLang)
	if err != nil {
		return cds, fmt.Errorf("error getting args for chaincode %s", err)
	}

	var targz io.Reader = bytes.NewBuffer(cds.CodePackage)
	//@@ CreateImageReq 생성 ( tar.gz 파일 형식 )
	cir := &container.CreateImageReq{CCID: ccintf.CCID{ChaincodeSpec: cds.ChaincodeSpec, NetworkID: chaincodeSupport.peerNetworkID, PeerID: chaincodeSupport.peerID}, Args: args, Reader: targz, Env: envs}

	vmtype, _ := chaincodeSupport.getVMType(cds)

	chaincodeLogger.Debugf("deploying chaincode %s(networkid:%s,peerid:%s)", chaincode, chaincodeSupport.peerNetworkID, chaincodeSupport.peerID)

	//create image and create container
	// @@ image를 생성, 컨테이너 생성.
	//@@ VMCReqIntf 의 종류에 따라, vm.Deploy(), vm.Start(), vm.Stop, vm.Destroy() 실행
	//@@ -> Deploy / Start / Stop / Destroy 는 docker 명령의 일반적인 의미와 동일
	_, err = container.VMCProcess(context, vmtype, cir)
	if err != nil {
		err = fmt.Errorf("Error starting container: %s", err)
	}

	return cds, err
}

// HandleChaincodeStream implements ccintf.HandleChaincodeStream for all vms to call with appropriate stream
//@@ HandleChaincodeStream() 실행
//@@ 	handler.processStream() 실행
//@@ 		handler.ChatStream.Recv() 실행 : stream 에서 데이터 수신
//@@ 		( 통신 에러 및 Data 에러 ) 처리
//@@ 		keep alive 인 경우, 다시 수신 시도
//@@ 		keep alive timeout 발생시, KEEPALIVE 요청 송신
//@@ 		수신한 ChaincodeMessage 에 대한 처리
//@@ 			QUERY_COMPLETED : Tracking대상에서 삭제 -> Payload 암호화 -> handler.responseNotifier 로 msg 전달
//@@ 			QUERY_ERROR : Tracking대상에서 삭제 -> handler.responseNotifier 로 msg 전달
//@@ 			INVOKE_QUERY : chaincode 실행 & 응답 처리 
//@@ 									-> handler.nextState 채널로 ChaincodeMessage 송신 및 응답 처리
//@@ 			수신된 Event 가 현재 State 에서 발생될 수 없는 것이면, 에러 처리
//@@ 			handler.FSM 의 State 를 전이(transition)
//@@ 		handler.nextState 채널에서 이벤트 발생 && Chaincode 로 응답을 보내줘야 한다면
//@@ 		nsInfo.msg 을 handler.ChatStream 을 통해 전송
func (chaincodeSupport *ChaincodeSupport) HandleChaincodeStream(ctxt context.Context, stream ccintf.ChaincodeStream) error {
	return HandleChaincodeStream(chaincodeSupport, ctxt, stream)
}

// Register the bidi stream entry point called by chaincode to register with the Peer.
func (chaincodeSupport *ChaincodeSupport) Register(stream pb.ChaincodeSupport_RegisterServer) error {
	return chaincodeSupport.HandleChaincodeStream(stream.Context(), stream)
}

// createTransactionMessage creates a transaction message.
// @@ 트랜잭션 메세지(ChaincodeMessage)를 생성
func createTransactionMessage(txid string, cMsg *pb.ChaincodeInput) (*pb.ChaincodeMessage, error) {
	payload, err := proto.Marshal(cMsg)
	if err != nil {
		fmt.Printf(err.Error())
		return nil, err
	}
	return &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_TRANSACTION, Payload: payload, Txid: txid}, nil
}

// createQueryMessage creates a query message.
// @@ 쿼리 메세지(ChaincodeMessage)를 생성
func createQueryMessage(txid string, cMsg *pb.ChaincodeInput) (*pb.ChaincodeMessage, error) {
	payload, err := proto.Marshal(cMsg)
	if err != nil {
		return nil, err
	}
	return &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_QUERY, Payload: payload, Txid: txid}, nil
}

// Execute executes a transaction and waits for it to complete until a timeout value.
// @@ 타임아웃 제한 시간내에 트랜잭션 실행 성공시에는 성공 response를 체인코드에 송신,
// @@ 타임아웃을 넘겼을 경우는 에러를 송신.
//@@ ChaincodeID 로 *chaincodeRTEnv 를 찾지 못하면 에러 처리
//@@ pb.Transaction 으로부터 pb.ChaincodeMessage.SecurityContext(msg) 설정
//@@ chrte.handler.sendExecuteMessage() 실행 --> response 채널 얻기
//@@ 	Tx == Transaction : handler.nextState 채널로 ChaincodeMessage 전송
//@@ 	Tx != Transaction : serialSend : 체인코드 메세지를 순차적으로 송신. (Lock 처리)
//@@ 	response 채널 리턴
//@@ select : response 채널 과 timeout 채널
//@@ handler 에서 Txid 를 삭제
//@@ response 리턴
func (chaincodeSupport *ChaincodeSupport) Execute(ctxt context.Context, chaincode string, msg *pb.ChaincodeMessage, timeout time.Duration, tx *pb.Transaction) (*pb.ChaincodeMessage, error) {
	chaincodeSupport.runningChaincodes.Lock()
	//we expect the chaincode to be running... sanity check
	//@@ ChaincodeID 로 *chaincodeRTEnv 를 찾지 못하면 에러 처리
	chrte, ok := chaincodeSupport.chaincodeHasBeenLaunched(chaincode)
	if !ok {
		chaincodeSupport.runningChaincodes.Unlock()
		chaincodeLogger.Debugf("cannot execute-chaincode is not running: %s", chaincode)
		return nil, fmt.Errorf("Cannot execute transaction or query for %s", chaincode)
	}
	chaincodeSupport.runningChaincodes.Unlock()

	var notfy chan *pb.ChaincodeMessage
	var err error
	//@@ sendExecuteMessage
	//@@ pb.Transaction 으로부터 pb.ChaincodeMessage.SecurityContext(msg) 설정
	//@@ Tx == Transaction : handler.nextState 채널로 ChaincodeMessage 전송
	//@@ Tx != Transaction : serialSend : 체인코드 메세지를 순차적으로 송신. (Lock 처리)
	//@@ response 채널 리턴
	if notfy, err = chrte.handler.sendExecuteMessage(msg, tx); err != nil {
		return nil, fmt.Errorf("Error sending %s: %s", msg.Type.String(), err)
	}
	var ccresp *pb.ChaincodeMessage
	//@@ select : response 채널 과 timeout 채널 
	select {
	case ccresp = <-notfy:
		//response is sent to user or calling chaincode. ChaincodeMessage_ERROR and ChaincodeMessage_QUERY_ERROR
		//are typically treated as error
	case <-time.After(timeout):
		err = fmt.Errorf("Timeout expired while executing transaction")
	}

	//our responsibility to delete transaction context if sendExecuteMessage succeeded
	//@@ handler 에서 Txid 를 삭제
	chrte.handler.deleteTxContext(msg.Txid)

	//@@ response 리턴
	return ccresp, err
}
