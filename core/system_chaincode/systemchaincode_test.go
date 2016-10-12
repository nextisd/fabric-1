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

package system_chaincode

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/hyperledger/fabric/core/chaincode"
	"github.com/hyperledger/fabric/core/db"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/core/system_chaincode/api"
	"github.com/hyperledger/fabric/core/system_chaincode/samplesyscc"
	"github.com/hyperledger/fabric/core/util"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/spf13/viper"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var testDBWrapper = db.NewTestDBWrapper()

// Invoke or query a chaincode.
func invoke(ctx context.Context, spec *pb.ChaincodeSpec, typ pb.Transaction_Type) (*pb.ChaincodeEvent, string, []byte, error) {
	chaincodeInvocationSpec := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}

	// Now create the Transactions message and send to Peer.
	//
	// 트랜잭션 메시지 생성, 피어에게 전송까지 테스트.
	uuid := util.GenerateUUID()

	var transaction *pb.Transaction
	var err error
	// NewChaincodeExecute() : invoke를 위한 tx 생성
	transaction, err = pb.NewChaincodeExecute(chaincodeInvocationSpec, uuid, typ)
	if err != nil {
		return nil, uuid, nil, fmt.Errorf("Error invoking chaincode: %s ", err)
	}

	var retval []byte
	var execErr error
	var ccevt *pb.ChaincodeEvent
	if typ == pb.Transaction_CHAINCODE_QUERY {
		retval, ccevt, execErr = chaincode.Execute(ctx, chaincode.GetChain(chaincode.DefaultChain), transaction)
	} else {
		ledger, _ := ledger.GetLedger()
		// 트랜잭션 배치 실행, ledger.currentID = "1"
		ledger.BeginTxBatch("1")
		retval, ccevt, execErr = chaincode.Execute(ctx, chaincode.GetChain(chaincode.DefaultChain), transaction)
		if err != nil {
			return nil, uuid, nil, fmt.Errorf("Error invoking chaincode: %s ", err)
		}
		ledger.CommitTxBatch("1", []*pb.Transaction{transaction}, nil, nil)
	}

	return ccevt, uuid, retval, execErr
}

func closeListenerAndSleep(l net.Listener) {
	if l != nil {
		l.Close()
		time.Sleep(2 * time.Second)
	}
}

// Test deploy of a transaction.
//
// t.TestExecuteDeploySysChaincode() : 트랜잭션 deploy 테스트
func TestExecuteDeploySysChaincode(t *testing.T) {
	testDBWrapper.CleanDB(t)
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	viper.Set("peer.fileSystemPath", "/var/hyperledger/test/tmpdb")

	//use a different address than what we usually use for "peer"
	//we override the peerAddress set in chaincode_support.go
	//
	// "peer" 일반적으로 쓰던 주소와 다른 주소를 사용함.
	peerAddress := "0.0.0.0:21726"
	lis, err := net.Listen("tcp", peerAddress)
	if err != nil {
		t.Fail()
		t.Logf("Error starting peer listener %s", err)
		return
	}
	// pb.PeerEndpoint 구조체
	//	ID      *PeerID
	//	Address string
	//	Type    PeerEndpoint_Type (0.UNDEFINED, 1.VALIDATOR, 2.NON_VALIDATOR)
	//	PkiID
	getPeerEndpoint := func() (*pb.PeerEndpoint, error) {
		return &pb.PeerEndpoint{ID: &pb.PeerID{Name: "testpeer"}, Address: peerAddress}, nil
	}

	ccStartupTimeout := time.Duration(5000) * time.Millisecond
	pb.RegisterChaincodeSupportServer(grpcServer, chaincode.NewChaincodeSupport(chaincode.DefaultChain, getPeerEndpoint, false, ccStartupTimeout, nil))

	go grpcServer.Serve(lis)

	var ctxt = context.Background()

	//set systemChaincodes to sample
	systemChaincodes = []*api.SystemChaincode{
		{
			Enabled:   true,
			Name:      "sample_syscc",
			Path:      "github.com/hyperledger/fabric/core/system_chaincode/samplesyscc",
			InitArgs:  [][]byte{},
			Chaincode: &samplesyscc.SampleSysCC{},
		},
	}

	// System chaincode has to be enabled
	//
	// 시스템 체인코드 환경 설정
	viper.Set("chaincode.system", map[string]string{"sample_syscc": "true"})
	RegisterSysCCs()

	url := "github.com/hyperledger/fabric/core/system_chaincode/sample_syscc"
	f := "putval"
	args := util.ToChaincodeArgs(f, "greeting", "hey there")

	// "putval" invoke를 위한 체인코드 스펙 세팅
	// 	key		: "sample_sysccgreeting"
	//	value 	: "hey there"
	spec := &pb.ChaincodeSpec{Type: 1, ChaincodeID: &pb.ChaincodeID{Name: "sample_syscc", Path: url}, CtorMsg: &pb.ChaincodeInput{Args: args}}

	// 체인코드 invoke : tx 생성, 피어 전송, tx 배치 실행에서 commit까지.
	_, _, _, err = invoke(ctxt, spec, pb.Transaction_CHAINCODE_INVOKE)
	if err != nil {
		closeListenerAndSleep(lis)
		t.Fail()
		t.Logf("Error invoking sample_syscc: %s", err)
		return
	}

	// "getval" invoke를 위한 체인코드 스펙 세팅
	// 	key		: "sample_sysccgreeting"
	f = "getval"
	args = util.ToChaincodeArgs(f, "greeting")
	spec = &pb.ChaincodeSpec{Type: 1, ChaincodeID: &pb.ChaincodeID{Name: "sample_syscc", Path: url}, CtorMsg: &pb.ChaincodeInput{Args: args}}
	_, _, _, err = invoke(ctxt, spec, pb.Transaction_CHAINCODE_QUERY)
	if err != nil {
		closeListenerAndSleep(lis)
		t.Fail()
		t.Logf("Error invoking sample_syscc: %s", err)
		return
	}

	cds := &pb.ChaincodeDeploymentSpec{ExecEnv: 1, ChaincodeSpec: &pb.ChaincodeSpec{Type: 1, ChaincodeID: &pb.ChaincodeID{Name: "sample_syscc", Path: url}, CtorMsg: &pb.ChaincodeInput{Args: args}}}

	chaincode.GetChain(chaincode.DefaultChain).Stop(ctxt, cds)

	closeListenerAndSleep(lis)
}

func TestMain(m *testing.M) {
	SetupTestConfig()
	os.Exit(m.Run())
}
