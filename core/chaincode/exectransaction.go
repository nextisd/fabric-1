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
	"errors"
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"

	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/events/producer"
	pb "github.com/hyperledger/fabric/protos"
)

//Execute - execute transaction or a query
// @@ 트랜잭션 실행 또는 쿼리
//@@ ledger (blockchain) 관리 객체 얻어옴 (객체는 전역 1개)
//@@ Confidentiality check
//@@ CHAINCODE_DEPLOY 인 경우
//@@		chain.Deploy(ctxt, t) 호출
//@@			Dup Check
//@@			VMCProcess() 호출 : 내부에서 vm.Deploy() 실행
//@@		chain.Launch(ctxt, t) 호출
//@@			launchAndWaitForRegister() 실행
//@@				container.StartImageReq 생성후 VMCProcesS() 실행 ( 내부 : vm.Start() )
//@@				readyNotify 채널에서 true 가 오면 정상, false 가 오면 실패
//@@			sendInitOrReady() 실행
//@@				handler.nextState 채널로 ChaincodeMessage 전송 & responseNotifier 생성
//@@				응답수신 대기 && 에러응답 처리
//@@ CHAINCODE_INVOKE  또는 CHAINCODE_QUERY 인 경우
//@@		chain.Launch(ctxt, t) 호출
//@@			launchAndWaitForRegister() 실행
//@@				container.StartImageReq 생성후 VMCProcesS() 실행 ( 내부 : vm.Start() )
//@@				readyNotify 채널에서 true 가 오면 정상, false 가 오면 실패
//@@			sendInitOrReady() 실행
//@@				handler.nextState 채널로 ChaincodeMessage 전송 & responseNotifier 생성
//@@				응답수신 대기 && 에러응답 처리
//@@			ChaincodeID, CtorMsg, err 리턴
//@@		INVOKE 또는 QUERY 용 Tx Msg 생성
//@@		chain.Execute(ctxt, chaincode, ccMsg, timeout, t) 호출
//@@			ChaincodeID 로 *chaincodeRTEnv 를 찾지 못하면 에러 처리
//@@			pb.Transaction 으로부터 pb.ChaincodeMessage.SecurityContext(msg) 설정
//@@			chrte.handler.sendExecuteMessage() 실행 --> response 채널 얻기
//@@ 			Tx == Transaction : handler.nextState 채널로 ChaincodeMessage 전송
//@@ 			Tx != Transaction : serialSend : 체인코드 메세지를 순차적으로 송신. (Lock 처리)
//@@ 			response 채널 리턴
//@@			select : response 채널 과 timeout 채널
//@@			handler 에서 Txid 를 삭제
//@@			response 리턴
//@@		return resp.Payload, resp.ChaincodeEvent,err
func Execute(ctxt context.Context, chain *ChaincodeSupport, t *pb.Transaction) ([]byte, *pb.ChaincodeEvent, error) {
	var err error

	// get a handle to ledger to mark the begin/finish of a tx
	// @@ 렛저에 접근 권한 얻기 -> 트랜잭션의 시작 또는 끝을 마킹하기 위함
	ledger, ledgerErr := ledger.GetLedger()
	if ledgerErr != nil {
		return nil, nil, fmt.Errorf("Failed to get handle to ledger (%s)", ledgerErr)
	}

	if secHelper := chain.getSecHelper(); nil != secHelper {
		var err error
		//@@ Confidentiality check
		t, err = secHelper.TransactionPreExecution(t)
		// Note that t is now decrypted and is a deep clone of the original input t
		if nil != err {
			return nil, nil, err
		}
	}
	// @@ 만약 deploy 라면,
	if t.Type == pb.Transaction_CHAINCODE_DEPLOY {
		//@@ ChaincodeDeploymentSpec 생성 ( Tx.Payload -> cds )
		//@@ ChaincodeID 로 *chaincodeRTEnv 찾아서 있으면 에러
		//@@ 입력된 chaincodeID에 속하는 arguments와 환경 변수를 get
		//@@ (args 에는 Path, ChaincodeName, peer.address 만 있음)
		//@@ CreateImageReq 생성 ( tar.gz 파일 형식 )
		//@@ VMCProcess() 호출 : 내부에서 vm.Deploy() 실행
		_, err := chain.Deploy(ctxt, t)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to deploy chaincode spec(%s)", err)
		}

		//launch and wait for ready
		//@@ 트랜잭션의 시작을 마킹하고, 렛저에 체인코드 런치, 그리고 트랜잭션 종료를 마킹.
		markTxBegin(ledger, t)
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
		_, _, err = chain.Launch(ctxt, t)
		if err != nil {
			markTxFinish(ledger, t, false)
			return nil, nil, fmt.Errorf("%s", err)
		}
		markTxFinish(ledger, t, true)
		// @@ 만약 invoke나 query 라면,
		// @@ chain.Launch -> chain.Execute
	} else if t.Type == pb.Transaction_CHAINCODE_INVOKE || t.Type == pb.Transaction_CHAINCODE_QUERY {
		//will launch if necessary (and wait for ready)
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
		cID, cMsg, err := chain.Launch(ctxt, t)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to launch chaincode spec(%s)", err)
		}

		//this should work because it worked above...
		chaincode := cID.Name

		if err != nil {
			return nil, nil, fmt.Errorf("Failed to stablish stream to container %s", chaincode)
		}

		// TODO: Need to comment next line and uncomment call to getTimeout, when transaction blocks are being created
		// @@ 블록 생성에 대한 타임 아웃 설정
		timeout := time.Duration(30000) * time.Millisecond
		//timeout, err := getTimeout(cID)

		if err != nil {
			return nil, nil, fmt.Errorf("Failed to retrieve chaincode spec(%s)", err)
		}

		//@@ INVOKE 또는 QUERY 용 Tx Msg 생성
		var ccMsg *pb.ChaincodeMessage
		if t.Type == pb.Transaction_CHAINCODE_INVOKE {
			ccMsg, err = createTransactionMessage(t.Txid, cMsg)
			if err != nil {
				return nil, nil, fmt.Errorf("Failed to transaction message(%s)", err)
			}
		} else {
			ccMsg, err = createQueryMessage(t.Txid, cMsg)
			if err != nil {
				return nil, nil, fmt.Errorf("Failed to query message(%s)", err)
			}
		}

		markTxBegin(ledger, t)
		//@@ ChaincodeID 로 *chaincodeRTEnv 를 찾지 못하면 에러 처리
		//@@ pb.Transaction 으로부터 pb.ChaincodeMessage.SecurityContext(msg) 설정
		//@@ chrte.handler.sendExecuteMessage() 실행 --> response 채널 얻기
		//@@ 	Tx == Transaction : handler.nextState 채널로 ChaincodeMessage 전송
		//@@ 	Tx != Transaction : serialSend : 체인코드 메세지를 순차적으로 송신. (Lock 처리)
		//@@ 	response 채널 리턴
		//@@ select : response 채널 과 timeout 채널
		//@@ handler 에서 Txid 를 삭제
		//@@ response 리턴
		resp, err := chain.Execute(ctxt, chaincode, ccMsg, timeout, t)
		if err != nil {
			// Rollback transaction
			// @@ 트랜잭션 실행 에러 발생시 롤백
			markTxFinish(ledger, t, false)
			return nil, nil, fmt.Errorf("Failed to execute transaction or query(%s)", err)
		} else if resp == nil {
			// Rollback transaction
			// @@ 응답 미수신시 롤백
			markTxFinish(ledger, t, false)
			return nil, nil, fmt.Errorf("Failed to receive a response for (%s)", t.Txid)
		} else { // @@ chain.Execute가 정상일 경우.
			if resp.ChaincodeEvent != nil {
				resp.ChaincodeEvent.ChaincodeID = chaincode
				resp.ChaincodeEvent.TxID = t.Txid
			}
			// 체인코드 응답이 _COMPLETED, _QUERY_COMPLETED 일 경우,
			if resp.Type == pb.ChaincodeMessage_COMPLETED || resp.Type == pb.ChaincodeMessage_QUERY_COMPLETED {
				// Success
				// 성공시, 트랜잭션 실행 종료점을 마킹
				markTxFinish(ledger, t, true)
				return resp.Payload, resp.ChaincodeEvent, nil
			} else if resp.Type == pb.ChaincodeMessage_ERROR || resp.Type == pb.ChaincodeMessage_QUERY_ERROR {
				// Rollback transaction
				// 실패시, 롤백
				markTxFinish(ledger, t, false)
				return nil, resp.ChaincodeEvent, fmt.Errorf("Transaction or query returned with failure: %s", string(resp.Payload))
			}
			markTxFinish(ledger, t, false)
			return resp.Payload, nil, fmt.Errorf("receive a response for (%s) but in invalid state(%d)", t.Txid, resp.Type)
		}

	} else {
		err = fmt.Errorf("Invalid transaction type %s", t.Type.String())
	}
	return nil, nil, err
}

//ExecuteTransactions - will execute transactions on the array one by one
//will return an array of errors one for each transaction. If the execution
//succeeded, array element will be nil. returns []byte of state hash or
//error
// @@ 복수개의 트랜잭션을 실행할 때, array를 이용하여 건바이 건으로 실행하고 그 응답 역시 array를 이용하여 리턴.
//@@ Tx Array 를 받아서, 개별 Tx 마다 chaincode.Execute() 호출
//@@		ledger (blockchain) 관리 객체 얻어옴 (객체는 전역 1개)
//@@		Confidentiality check
//@@		CHAINCODE_DEPLOY 인 경우
//@@			chain.Deploy(ctxt, t) 호출
//@@				Dup Check
//@@				VMCProcess() 호출 : 내부에서 vm.Deploy() 실행
//@@			chain.Launch(ctxt, t) 호출
//@@				launchAndWaitForRegister() 실행
//@@					container.StartImageReq 생성후 VMCProcesS() 실행 ( 내부 : vm.Start() )
//@@					readyNotify 채널에서 true 가 오면 정상, false 가 오면 실패
//@@				sendInitOrReady() 실행
//@@					handler.nextState 채널로 ChaincodeMessage 전송 & responseNotifier 생성
//@@					응답수신 대기 && 에러응답 처리
//@@		CHAINCODE_INVOKE  또는 CHAINCODE_QUERY 인 경우
//@@			chain.Launch(ctxt, t) 호출
//@@				launchAndWaitForRegister() 실행
//@@					container.StartImageReq 생성후 VMCProcesS() 실행 ( 내부 : vm.Start() )
//@@					readyNotify 채널에서 true 가 오면 정상, false 가 오면 실패
//@@				sendInitOrReady() 실행
//@@					handler.nextState 채널로 ChaincodeMessage 전송 & responseNotifier 생성
//@@					응답수신 대기 && 에러응답 처리
//@@				ChaincodeID, CtorMsg, err 리턴
//@@			INVOKE 또는 QUERY 용 Tx Msg 생성
//@@			chain.Execute(ctxt, chaincode, ccMsg, timeout, t) 호출
//@@				ChaincodeID 로 *chaincodeRTEnv 를 찾지 못하면 에러 처리
//@@				pb.Transaction 으로부터 pb.ChaincodeMessage.SecurityContext(msg) 설정
//@@				chrte.handler.sendExecuteMessage() 실행 --> response 채널 얻기
//@@					Tx == Transaction : handler.nextState 채널로 ChaincodeMessage 전송
//@@					Tx != Transaction : serialSend : 체인코드 메세지를 순차적으로 송신. (Lock 처리)
//@@					response 채널 리턴
//@@				select : response 채널 과 timeout 채널
//@@				handler 에서 Txid 를 삭제
//@@				response 리턴
//@@			return resp.Payload, resp.ChaincodeEvent,err
func ExecuteTransactions(ctxt context.Context, cname ChainName, xacts []*pb.Transaction) (succeededTXs []*pb.Transaction, stateHash []byte, ccevents []*pb.ChaincodeEvent, txerrs []error, err error) {
	var chain = GetChain(cname) // @@ 체인 찾기
	if chain == nil {
		// TODO: We should never get here, but otherwise a good reminder to better handle
		panic(fmt.Sprintf("[ExecuteTransactions]Chain %s not found\n", cname))
	}

	txerrs = make([]error, len(xacts))
	ccevents = make([]*pb.ChaincodeEvent, len(xacts))
	var succeededTxs = make([]*pb.Transaction, 0)
	for i, t := range xacts {
		//@@ ledger (blockchain) 관리 객체 얻어옴 (객체는 전역 1개)
		//@@ Confidentiality check
		//@@ CHAINCODE_DEPLOY 인 경우
		//@@		chain.Deploy(ctxt, t) 호출
		//@@			Dup Check
		//@@			VMCProcess() 호출 : 내부에서 vm.Deploy() 실행
		//@@		chain.Launch(ctxt, t) 호출
		//@@			launchAndWaitForRegister() 실행
		//@@				container.StartImageReq 생성후 VMCProcesS() 실행 ( 내부 : vm.Start() )
		//@@				readyNotify 채널에서 true 가 오면 정상, false 가 오면 실패
		//@@			sendInitOrReady() 실행
		//@@				handler.nextState 채널로 ChaincodeMessage 전송 & responseNotifier 생성
		//@@				응답수신 대기 && 에러응답 처리
		//@@ CHAINCODE_INVOKE  또는 CHAINCODE_QUERY 인 경우
		//@@		chain.Launch(ctxt, t) 호출
		//@@			launchAndWaitForRegister() 실행
		//@@				container.StartImageReq 생성후 VMCProcesS() 실행 ( 내부 : vm.Start() )
		//@@				readyNotify 채널에서 true 가 오면 정상, false 가 오면 실패
		//@@			sendInitOrReady() 실행
		//@@				handler.nextState 채널로 ChaincodeMessage 전송 & responseNotifier 생성
		//@@				응답수신 대기 && 에러응답 처리
		//@@			ChaincodeID, CtorMsg, err 리턴
		//@@		INVOKE 또는 QUERY 용 Tx Msg 생성
		//@@		chain.Execute(ctxt, chaincode, ccMsg, timeout, t) 호출
		//@@			ChaincodeID 로 *chaincodeRTEnv 를 찾지 못하면 에러 처리
		//@@			pb.Transaction 으로부터 pb.ChaincodeMessage.SecurityContext(msg) 설정
		//@@			chrte.handler.sendExecuteMessage() 실행 --> response 채널 얻기
		//@@ 			Tx == Transaction : handler.nextState 채널로 ChaincodeMessage 전송
		//@@ 			Tx != Transaction : serialSend : 체인코드 메세지를 순차적으로 송신. (Lock 처리)
		//@@ 			response 채널 리턴
		//@@			select : response 채널 과 timeout 채널
		//@@			handler 에서 Txid 를 삭제
		//@@			response 리턴
		//@@		return resp.Payload, resp.ChaincodeEvent,err
		_, ccevents[i], txerrs[i] = Execute(ctxt, chain, t)
		if txerrs[i] == nil { // @@ loop돌면서 tx 처리
			succeededTxs = append(succeededTxs, t)
		} else {
			sendTxRejectedEvent(xacts[i], txerrs[i].Error())
		}
	}

	var lgr *ledger.Ledger
	lgr, err = ledger.GetLedger()
	if err == nil {
		stateHash, err = lgr.GetTempStateHash() // @@ 에러가 아니라면, 상태 렛저에서 상태값을 읽어서 리턴.
	}

	return succeededTxs, stateHash, ccevents, txerrs, err
}

// GetSecureContext returns the security context from the context object or error
// Security context is nil if security is off from core.yaml file
// func GetSecureContext(ctxt context.Context) (crypto.Peer, error) {
// 	var err error
// 	temp := ctxt.Value("security")
// 	if nil != temp {
// 		if secCxt, ok := temp.(crypto.Peer); ok {
// 			return secCxt, nil
// 		}
// 		err = errors.New("Failed to convert security context type")
// 	}
// 	return nil, err
// }

var errFailedToGetChainCodeSpecForTransaction = errors.New("Failed to get ChainCodeSpec from Transaction")

func getTimeout(cID *pb.ChaincodeID) (time.Duration, error) {
	ledger, err := ledger.GetLedger()
	if err == nil {
		chaincodeID := cID.Name
		txID, err := ledger.GetState(chaincodeID, "github.com_openblockchain_obc-peer_chaincode_id", true)
		if err == nil {
			tx, err := ledger.GetTransactionByID(string(txID))
			if err == nil {
				chaincodeDeploymentSpec := &pb.ChaincodeDeploymentSpec{}
				proto.Unmarshal(tx.Payload, chaincodeDeploymentSpec)
				chaincodeSpec := chaincodeDeploymentSpec.GetChaincodeSpec()
				timeout := time.Duration(time.Duration(chaincodeSpec.Timeout) * time.Millisecond)
				return timeout, nil
			}
		}
	}

	return -1, errFailedToGetChainCodeSpecForTransaction
}

// @@ 렛저에 트랜잭션 실행 시작 지점을 마킹
func markTxBegin(ledger *ledger.Ledger, t *pb.Transaction) {
	if t.Type == pb.Transaction_CHAINCODE_QUERY {
		return
	}
	ledger.TxBegin(t.Txid)
}

// @@ 렛저에 트랜잭션 실행 종료 지점을 마킹
func markTxFinish(ledger *ledger.Ledger, t *pb.Transaction, successful bool) {
	if t.Type == pb.Transaction_CHAINCODE_QUERY {
		return
	}
	ledger.TxFinished(t.Txid, successful)
}

// @@ 에러가 발생했음을 알리는 이벤트 송신
func sendTxRejectedEvent(tx *pb.Transaction, errorMsg string) {
	producer.Send(producer.CreateRejectionEvent(tx, errorMsg))
}
