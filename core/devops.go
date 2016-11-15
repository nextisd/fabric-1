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

package core

import (
	"errors"
	"fmt"
	"strings"

	"github.com/op/go-logging"
	"github.com/spf13/viper"
	"golang.org/x/net/context"

	"encoding/asn1"
	"encoding/base64"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/core/chaincode"
	"github.com/hyperledger/fabric/core/chaincode/platforms"
	"github.com/hyperledger/fabric/core/container"
	crypto "github.com/hyperledger/fabric/core/crypto"
	"github.com/hyperledger/fabric/core/peer"
	"github.com/hyperledger/fabric/core/util"
	pb "github.com/hyperledger/fabric/protos"
)

var devopsLogger = logging.MustGetLogger("devops")

// NewDevopsServer creates and returns a new Devops server instance.
func NewDevopsServer(coord peer.MessageHandlerCoordinator) *Devops {
	d := new(Devops)
	d.coord = coord
	d.isSecurityEnabled = viper.GetBool("security.enabled")
	d.bindingMap = &bindingMap{m: make(map[string]crypto.TransactionHandler)}
	return d
}

// bindingMap Used to store map of binding to TransactionHandler
type bindingMap struct {
	sync.RWMutex
	m map[string]crypto.TransactionHandler
}

// Devops implementation of Devops services
type Devops struct {
	coord             peer.MessageHandlerCoordinator
	isSecurityEnabled bool
	bindingMap        *bindingMap
}

func (b *bindingMap) getKeyFromBinding(binding []byte) string {
	return base64.StdEncoding.EncodeToString(binding)
}

func (b *bindingMap) addBinding(bindingToAdd []byte, txHandler crypto.TransactionHandler) {
	b.Lock()
	defer b.Unlock()
	key := b.getKeyFromBinding(bindingToAdd)
	b.m[key] = txHandler
}

func (b *bindingMap) getTxHandlerForBinding(binding []byte) (crypto.TransactionHandler, error) {
	b.Lock()
	defer b.Unlock()
	key := b.getKeyFromBinding(binding)
	txHandler, ok := b.m[key]
	if ok != true {
		// TXhandler not found by key, return error
		return nil, fmt.Errorf("Transaction handler not found for binding key = %s", key)
	}
	return txHandler, nil
}

// Login establishes the security context with the Devops service
func (d *Devops) Login(ctx context.Context, secret *pb.Secret) (*pb.Response, error) {
	if err := crypto.RegisterClient(secret.EnrollId, nil, secret.EnrollId, secret.EnrollSecret); nil != err {
		return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}, nil
	}
	return &pb.Response{Status: pb.Response_SUCCESS}, nil

	// TODO: Handle timeout and expiration
}

// Build builds the supplied chaincode image
//@@ CheckSpec() 호출
//@@		platform type 에 따라, platform.ValidateSpec(spec) 호출
//@@		현재, platform : car, golang, java
//@@			ValidateSpec for car : 무조건 성공
//@@			ValidateSpec for golang
//@@				URL Parse : String -> URL structure
//@@				URL 이 아닌 경우 : $GOPATH/src 아래에 path 가 있는지 확인
//@@			ValidateSpec for java
//@@				URL Parse : String -> URL structure
//@@				URL 이 아닌 경우 : nil 리턴 (성공)
//@@ container.NewVM() 호출
//@@		cutil.NewDockerClient() 호출
//@@			docker client 생성
//@@			core.yaml 에서 필요한 parameter
//@@			"vm.endpoint" , "vm.docker.tls.enabled"
//@@			vm.docker.tls.enabled = true
//@@			--> "vm.docker.tls.cert.file" / "vm.docker.tls.key.file" / "vm.docker.tls.ca.file"
//@@		docker client 를 가진 VM 생성하여 리턴
//@@ vm.BuildChaincodeContainer() 호출
//@@		GetChaincodePackageBytes() 호출
//@@			platform.WritePackage() 호출
//@@				1.spec.ChaincodeID.Name에 Hash값 세팅
//@@				2.dockerFileContents 작성 : chaincode.golang.Dockerfile +
//@@					"RUN go install %s && cp src/github.com/hyperledger/fabric/peer/core.yaml $GOPATH/bin
//@@					 && mv $GOPATH/bin/%s $GOPATH/bin/%s",
//@@					urlLocation, chaincodeGoName, spec.ChaincodeID.Name"
//@@				3.Dockerfile 생성
//@@			platform.WritePackage(spec, tw) 호출
//@@				generateHashcode() 호출
//@@					codegopath 를 구함 ( path 처음이 "http://" 또는 "https://" 경우 ishttp = true )
//@@ 					ishttp == true 인 경우, getCodeFromHTTP() 호출
//@@							$GOPATH/_usercode_/임시디렉토리 리턴
//@@ 					ishttp != true 인 경우, getCodeFromFS() 호출
//@@							$GOPATH 의 첫번째 path 리턴
//@@					codegopath/src/path 존재여부 체크 ( path 에서 http:// 등은 제외 )
//@@					util.GenerateHashFromSignature() 호출
//@@						sha3.ShakeSum256(ctorbytes) 호출 : ctorbytes 의 hash 리턴
//@@					hashFilesInDir() 호출
//@@						rootDir/dir 아래에 있는 모든 file 에 대해 다음 수행
//@@							directory 면, 그 안에 있는 파일에 대해 recursive 하게 수행
//@@							file 이면, 읽어서 hash 를 구함 ( hash 는 파일마다 새로 계산 )
//@@						마지막 hash 리턴
//@@					hash hex string 리턴  (spec.ChaincodeID.Name 으로 세팅)
//@@				writeChaincodePackage() 호출
//@@					chaincode path 에서 마지막 디렉토리 이름이 chaincodeGoName
//@@					dockerfile 에 추가
//@@						"RUN go install <urlLocation> && "
//@@						"cp src/github.com/hyperledger/fabric/peer/core.yaml $GOPATH/bin && "
//@@						"mv $GOPATH/bin/<chaincodeGoName> $GOPATH/bin/<spec.ChaincodeID.Name>"
//@@					core.yaml 에 "peer.tls.enabled = true" 면, 아래 추가
//@@					"COPY src/certs/cert.pem <"peer.tls.cert.file">"
//@@					dockerfile 에는 core.yaml 에 있는 "chaincode.golang.Dockerfile" 의 내용을 먼저 write
//@@					tar 파일에 Dockerfile 추가
//@@					cutil.WriteGopathSrc() 호출
//@@						WriteFolderToTarPackage() 호출
//@@							rootDirectory : $GOPATH/src, urlLocation (http:// 제외한 path) 제외
//@@							대상 파일 : "*.c", "*.h", "*.go", "*.yaml", "*.json"
//@@						viper.GetBool("peer.tls.enabled") == true 인 경우
//@@							peer 의 TLS Cert 를 tar 에 추가 ( core.yaml "peer.tls.cert.file" )
//@@					err 리턴 (정상일 경우, nil)
//@@				err 리턴 (정상일 경우, nil)
//@@			tar file 을 []byte 로 리턴
//@@		buildChaincodeContainerUsingDockerfilePackageBytes() 호출
//@@			Image Build Option 생성
//@@			BuildImage() 호출
//@@				docker HTTP 에 Image 생성 요청송신/응답처리
//@@			err 리턴 (정상일 경우, nil)
//@@		chaincodePkgBytes, nil 리턴
//@@ ChaincodeDeploymentSpec 생성/리턴
func (*Devops) Build(context context.Context, spec *pb.ChaincodeSpec) (*pb.ChaincodeDeploymentSpec, error) {
	mode := viper.GetString("chaincode.mode")
	var codePackageBytes []byte
	if mode != chaincode.DevModeUserRunsChaincode {
		devopsLogger.Debugf("Received build request for chaincode spec: %v", spec)
		//@@ platform type 에 따라, platform.ValidateSpec(spec) 호출
		//@@ 현재, platform : car, golang, java
		//@@		ValidateSpec for car : 무조건 성공
		//@@		ValidateSpec for golang
		//@@			URL Parse : String -> URL structure
		//@@			URL 이 아닌 경우 : $GOPATH/src 아래에 path 가 있는지 확인
		//@@		ValidateSpec for java
		//@@			URL Parse : String -> URL structure
		//@@			URL 이 아닌 경우 : nil 리턴 (성공)
		if err := CheckSpec(spec); err != nil {
			return nil, err
		}

		//@@ cutil.NewDockerClient() 호출
		//@@		docker client 생성
		//@@		core.yaml 에서 필요한 parameter
		//@@		"vm.endpoint" , "vm.docker.tls.enabled"
		//@@		vm.docker.tls.enabled = true
		//@@		--> "vm.docker.tls.cert.file" / "vm.docker.tls.key.file" / "vm.docker.tls.ca.file"
		//@@ docker client 를 가진 VM 생성하여 리턴
		vm, err := container.NewVM()
		if err != nil {
			return nil, fmt.Errorf("Error getting vm")
		}

		//@@ GetChaincodePackageBytes() 호출
		//@@		platform.WritePackage() 호출
		//@@			1.spec.ChaincodeID.Name에 Hash값 세팅
		//@@			2.dockerFileContents 작성 : chaincode.golang.Dockerfile +
		//@@				"RUN go install %s && cp src/github.com/hyperledger/fabric/peer/core.yaml $GOPATH/bin
		//@@				 && mv $GOPATH/bin/%s $GOPATH/bin/%s",
		//@@				urlLocation, chaincodeGoName, spec.ChaincodeID.Name"
		//@@			3.Dockerfile 생성
		//@@		platform.WritePackage(spec, tw) 호출
		//@@			generateHashcode() 호출
		//@@				codegopath 를 구함 ( path 처음이 "http://" 또는 "https://" 경우 ishttp = true )
		//@@ 				ishttp == true 인 경우, getCodeFromHTTP() 호출
		//@@						$GOPATH/_usercode_/임시디렉토리 리턴
		//@@ 				ishttp != true 인 경우, getCodeFromFS() 호출
		//@@						$GOPATH 의 첫번째 path 리턴
		//@@				codegopath/src/path 존재여부 체크 ( path 에서 http:// 등은 제외 )
		//@@				util.GenerateHashFromSignature() 호출
		//@@					sha3.ShakeSum256(ctorbytes) 호출 : ctorbytes 의 hash 리턴
		//@@				hashFilesInDir() 호출
		//@@					rootDir/dir 아래에 있는 모든 file 에 대해 다음 수행
		//@@						directory 면, 그 안에 있는 파일에 대해 recursive 하게 수행
		//@@						file 이면, 읽어서 hash 를 구함 ( hash 는 파일마다 새로 계산 )
		//@@					마지막 hash 리턴
		//@@				hash hex string 리턴  (spec.ChaincodeID.Name 으로 세팅)
		//@@			writeChaincodePackage() 호출
		//@@				chaincode path 에서 마지막 디렉토리 이름이 chaincodeGoName
		//@@				dockerfile 에 추가
		//@@					"RUN go install <urlLocation> && "
		//@@					"cp src/github.com/hyperledger/fabric/peer/core.yaml $GOPATH/bin && "
		//@@					"mv $GOPATH/bin/<chaincodeGoName> $GOPATH/bin/<spec.ChaincodeID.Name>"
		//@@				core.yaml 에 "peer.tls.enabled = true" 면, 아래 추가
		//@@				"COPY src/certs/cert.pem <"peer.tls.cert.file">"
		//@@				dockerfile 에는 core.yaml 에 있는 "chaincode.golang.Dockerfile" 의 내용을 먼저 write
		//@@				tar 파일에 Dockerfile 추가
		//@@				cutil.WriteGopathSrc() 호출
		//@@					WriteFolderToTarPackage() 호출
		//@@						rootDirectory : $GOPATH/src, urlLocation (http:// 제외한 path) 제외
		//@@						대상 파일 : "*.c", "*.h", "*.go", "*.yaml", "*.json"
		//@@					viper.GetBool("peer.tls.enabled") == true 인 경우
		//@@						peer 의 TLS Cert 를 tar 에 추가 ( core.yaml "peer.tls.cert.file" )
		//@@				err 리턴 (정상일 경우, nil)
		//@@			err 리턴 (정상일 경우, nil)
		//@@		tar file 을 []byte 로 리턴
		//@@ buildChaincodeContainerUsingDockerfilePackageBytes() 호출
		//@@		Image Build Option 생성
		//@@		BuildImage() 호출
		//@@			docker HTTP 에 Image 생성 요청송신/응답처리
		//@@		err 리턴 (정상일 경우, nil)
		//@@ chaincodePkgBytes, nil 리턴
		codePackageBytes, err = vm.BuildChaincodeContainer(spec)
		if err != nil {
			devopsLogger.Error(fmt.Sprintf("%s", err))
			return nil, err
		}
	}
	chaincodeDeploymentSpec := &pb.ChaincodeDeploymentSpec{ChaincodeSpec: spec, CodePackage: codePackageBytes}
	return chaincodeDeploymentSpec, nil
}

// get chaincode bytes
func (*Devops) getChaincodeBytes(context context.Context, spec *pb.ChaincodeSpec) (*pb.ChaincodeDeploymentSpec, error) {
	mode := viper.GetString("chaincode.mode")
	var codePackageBytes []byte
	if mode != chaincode.DevModeUserRunsChaincode {
		devopsLogger.Debugf("Received build request for chaincode spec: %v", spec)
		var err error
		if err = CheckSpec(spec); err != nil {
			return nil, err
		}

		codePackageBytes, err = container.GetChaincodePackageBytes(spec)
		if err != nil {
			err = fmt.Errorf("Error getting chaincode package bytes: %s", err)
			devopsLogger.Error(fmt.Sprintf("%s", err))
			return nil, err
		}
	}
	chaincodeDeploymentSpec := &pb.ChaincodeDeploymentSpec{ChaincodeSpec: spec, CodePackage: codePackageBytes}
	return chaincodeDeploymentSpec, nil
}

// Deploy deploys the supplied chaincode image to the validators through a transaction
func (d *Devops) Deploy(ctx context.Context, spec *pb.ChaincodeSpec) (*pb.ChaincodeDeploymentSpec, error) {
	// get the deployment spec
	chaincodeDeploymentSpec, err := d.getChaincodeBytes(ctx, spec)

	if err != nil {
		devopsLogger.Error(fmt.Sprintf("Error deploying chaincode spec: %v\n\n error: %s", spec, err))
		return nil, err
	}

	// Now create the Transactions message and send to Peer.

	transID := chaincodeDeploymentSpec.ChaincodeSpec.ChaincodeID.Name

	var tx *pb.Transaction
	var sec crypto.Client

	if peer.SecurityEnabled() {
		if devopsLogger.IsEnabledFor(logging.DEBUG) {
			devopsLogger.Debugf("Initializing secure devops using context %s", spec.SecureContext)
		}
		sec, err = crypto.InitClient(spec.SecureContext, nil)
		defer crypto.CloseClient(sec)

		// remove the security context since we are no longer need it down stream
		spec.SecureContext = ""

		if nil != err {
			return nil, err
		}

		if devopsLogger.IsEnabledFor(logging.DEBUG) {
			devopsLogger.Debugf("Creating secure transaction %s", transID)
		}
		tx, err = sec.NewChaincodeDeployTransaction(chaincodeDeploymentSpec, transID, spec.Attributes...)
		if nil != err {
			return nil, err
		}
	} else {
		if devopsLogger.IsEnabledFor(logging.DEBUG) {
			devopsLogger.Debugf("Creating deployment transaction (%s)", transID)
		}
		tx, err = pb.NewChaincodeDeployTransaction(chaincodeDeploymentSpec, transID)
		if err != nil {
			return nil, fmt.Errorf("Error deploying chaincode: %s ", err)
		}
	}

	if devopsLogger.IsEnabledFor(logging.DEBUG) {
		devopsLogger.Debugf("Sending deploy transaction (%s) to validator", tx.Txid)
	}
	resp := d.coord.ExecuteTransaction(tx)
	if resp.Status == pb.Response_FAILURE {
		err = fmt.Errorf(string(resp.Msg))
	}

	return chaincodeDeploymentSpec, err
}

func (d *Devops) invokeOrQuery(ctx context.Context, chaincodeInvocationSpec *pb.ChaincodeInvocationSpec, attributes []string, invoke bool) (*pb.Response, error) {

	if chaincodeInvocationSpec.ChaincodeSpec.ChaincodeID.Name == "" {
		return nil, fmt.Errorf("name not given for invoke/query")
	}

	// Now create the Transactions message and send to Peer.
	var customIDgenAlg = strings.ToLower(chaincodeInvocationSpec.IdGenerationAlg)
	var id string
	var generr error
	if invoke {
		if customIDgenAlg != "" {
			ctorbytes, merr := asn1.Marshal(*chaincodeInvocationSpec.ChaincodeSpec.CtorMsg)
			if merr != nil {
				return nil, fmt.Errorf("Error marshalling constructor: %s", merr)
			}
			id, generr = util.GenerateIDWithAlg(customIDgenAlg, ctorbytes)
			if generr != nil {
				return nil, generr
			}
		} else {
			id = util.GenerateUUID()
		}
	} else {
		id = util.GenerateUUID()
	}
	devopsLogger.Infof("Transaction ID: %v", id)
	var transaction *pb.Transaction
	var err error
	var sec crypto.Client
	if peer.SecurityEnabled() {
		if devopsLogger.IsEnabledFor(logging.DEBUG) {
			devopsLogger.Debugf("Initializing secure devops using context %s", chaincodeInvocationSpec.ChaincodeSpec.SecureContext)
		}
		sec, err = crypto.InitClient(chaincodeInvocationSpec.ChaincodeSpec.SecureContext, nil)
		defer crypto.CloseClient(sec)
		// remove the security context since we are no longer need it down stream
		chaincodeInvocationSpec.ChaincodeSpec.SecureContext = ""
		if nil != err {
			return nil, err
		}
	}

	transaction, err = d.createExecTx(chaincodeInvocationSpec, attributes, id, invoke, sec)
	if err != nil {
		return nil, err
	}
	if devopsLogger.IsEnabledFor(logging.DEBUG) {
		devopsLogger.Debugf("Sending invocation transaction (%s) to validator", transaction.Txid)
	}
	resp := d.coord.ExecuteTransaction(transaction)
	if resp.Status == pb.Response_FAILURE {
		err = fmt.Errorf(string(resp.Msg))
	} else {
		if !invoke && nil != sec && viper.GetBool("security.privacy") {
			if resp.Msg, err = sec.DecryptQueryResult(transaction, resp.Msg); nil != err {
				devopsLogger.Errorf("Failed decrypting query transaction result %s", string(resp.Msg[:]))
				//resp = &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}
			}
		}
	}
	return resp, err
}

func (d *Devops) createExecTx(spec *pb.ChaincodeInvocationSpec, attributes []string, uuid string, invokeTx bool, sec crypto.Client) (*pb.Transaction, error) {
	var tx *pb.Transaction
	var err error

	//TODO What should we do with the attributes
	if nil != sec {
		if devopsLogger.IsEnabledFor(logging.DEBUG) {
			devopsLogger.Debugf("Creating secure invocation transaction %s", uuid)
		}
		if invokeTx {
			tx, err = sec.NewChaincodeExecute(spec, uuid, attributes...)
		} else {
			tx, err = sec.NewChaincodeQuery(spec, uuid, attributes...)
		}
		if nil != err {
			return nil, err
		}
	} else {
		if devopsLogger.IsEnabledFor(logging.DEBUG) {
			devopsLogger.Debugf("Creating invocation transaction (%s)", uuid)
		}
		var t pb.Transaction_Type
		if invokeTx {
			t = pb.Transaction_CHAINCODE_INVOKE
		} else {
			t = pb.Transaction_CHAINCODE_QUERY
		}
		tx, err = pb.NewChaincodeExecute(spec, uuid, t)
		if nil != err {
			return nil, err
		}
	}
	return tx, nil
}

// Invoke performs the supplied invocation on the specified chaincode through a transaction
func (d *Devops) Invoke(ctx context.Context, chaincodeInvocationSpec *pb.ChaincodeInvocationSpec) (*pb.Response, error) {
	return d.invokeOrQuery(ctx, chaincodeInvocationSpec, chaincodeInvocationSpec.ChaincodeSpec.Attributes, true)
}

// Query performs the supplied query on the specified chaincode through a transaction
func (d *Devops) Query(ctx context.Context, chaincodeInvocationSpec *pb.ChaincodeInvocationSpec) (*pb.Response, error) {
	return d.invokeOrQuery(ctx, chaincodeInvocationSpec, chaincodeInvocationSpec.ChaincodeSpec.Attributes, false)
}

// CheckSpec to see if chaincode resides within current package capture for language.
//@@ platform type 에 따라, platform.ValidateSpec(spec) 호출
//@@ 현재, platform : car, golang, java
//@@ ValidateSpec for car
//@@		무조건 성공
//@@ ValidateSpec for golang 
//@@		URL Parse : String -> URL structure.
//@@		URL 이 아니면 $GOPATH/src 아래에서 path 가 있는지 확인
//@@ ValidateSpec for java
//@@		URL Parse : String -> URL structure.
//@@		현재, URL 이 아닌 경우는 그냥 성공
func CheckSpec(spec *pb.ChaincodeSpec) error {
	// Don't allow nil value
	if spec == nil {
		return errors.New("Expected chaincode specification, nil received")
	}

	platform, err := platforms.Find(spec.Type)
	if err != nil {
		return fmt.Errorf("Failed to determine platform type: %s", err)
	}

	return platform.ValidateSpec(spec)
}

// EXP_GetApplicationTCert retrieves an application TCert for the supplied user
func (d *Devops) EXP_GetApplicationTCert(ctx context.Context, secret *pb.Secret) (*pb.Response, error) {
	var sec crypto.Client
	var err error

	if d.isSecurityEnabled {
		if devopsLogger.IsEnabledFor(logging.DEBUG) {
			devopsLogger.Debug("Initializing secure devops using context %s", secret.EnrollId)
		}
		sec, err = crypto.InitClient(secret.EnrollId, nil)
		defer crypto.CloseClient(sec)

		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}, nil
		}

		devopsLogger.Debug("Getting TCert for id: %s", secret.EnrollId)
		tcertHandler, err := sec.GetTCertificateHandlerNext()
		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}, nil
		}
		certDER := tcertHandler.GetCertificate()
		return &pb.Response{Status: pb.Response_SUCCESS, Msg: certDER}, nil
	}
	devopsLogger.Warning("Security NOT enabled")
	return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte("Security NOT enabled")}, nil
	// TODO: Handle timeout and expiration
}

// EXP_PrepareForTx prepares a binding/TXHandler pair to be used in subsequent TX
func (d *Devops) EXP_PrepareForTx(ctx context.Context, secret *pb.Secret) (*pb.Response, error) {
	var sec crypto.Client
	var err error
	var txHandler crypto.TransactionHandler
	var binding []byte

	if d.isSecurityEnabled {
		if devopsLogger.IsEnabledFor(logging.DEBUG) {
			devopsLogger.Debug("Initializing secure devops using context %s", secret.EnrollId)
		}
		sec, err = crypto.InitClient(secret.EnrollId, nil)
		defer crypto.CloseClient(sec)

		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}, nil
		}

		devopsLogger.Debug("Getting TXHandler for id: %s", secret.EnrollId)
		tcertHandler, err := sec.GetTCertificateHandlerNext()
		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}, nil
		}
		txHandler, err = tcertHandler.GetTransactionHandler()
		binding, err = txHandler.GetBinding()
		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}, nil
		}
		// Now add to binding map
		d.bindingMap.addBinding(binding, txHandler)
		return &pb.Response{Status: pb.Response_SUCCESS, Msg: binding}, nil
	}
	devopsLogger.Warning("Security NOT enabled")
	return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte("Security NOT enabled")}, nil
	// TODO: Handle timeout and expiration
}

// EXP_ProduceSigma produces a sigma as []byte and returns in response
func (d *Devops) EXP_ProduceSigma(ctx context.Context, sigmaInput *pb.SigmaInput) (*pb.Response, error) {
	var sec crypto.Client
	var err error
	var sigma []byte
	secret := sigmaInput.Secret

	type RBACMetatdata struct {
		Cert  []byte
		Sigma []byte
	}

	if d.isSecurityEnabled {
		if devopsLogger.IsEnabledFor(logging.DEBUG) {
			devopsLogger.Debug("Initializing secure devops using context %s", secret.EnrollId)
		}
		sec, err = crypto.InitClient(secret.EnrollId, nil)
		defer crypto.CloseClient(sec)

		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}, nil
		}

		devopsLogger.Debug("Getting TCertHandler for id: %s, from DER = %s", secret.EnrollId, sigmaInput.AppTCert)
		tcertHandler, err := sec.GetTCertificateHandlerFromDER(sigmaInput.AppTCert)
		//tcertHandler, err := sec.GetTCertificateHandlerNext()
		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(fmt.Errorf("Error getting TCertHandler from DER:  %s", err).Error())}, nil
		}
		tcert := sigmaInput.AppTCert //tcertHandler.GetCertificate()
		sigma, err = tcertHandler.Sign(append(tcert, sigmaInput.Data...))
		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(fmt.Errorf("Error signing with TCertHandler from DER:  %s", err).Error())}, nil
		}
		// Produce the SigmaOutput
		asn1Encoding, err := asn1.Marshal(RBACMetatdata{Cert: tcert, Sigma: sigma})
		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}, nil
		}
		sigmaOutput := &pb.SigmaOutput{Tcert: tcert, Sigma: sigma, Asn1Encoding: asn1Encoding}
		sigmaOutputBytes, err := proto.Marshal(sigmaOutput)
		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}, nil
		}
		return &pb.Response{Status: pb.Response_SUCCESS, Msg: sigmaOutputBytes}, nil
	}
	devopsLogger.Warning("Security NOT enabled")
	return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte("Security NOT enabled")}, nil

}

// EXP_ExecuteWithBinding executes a transaction with a specific binding/TXHandler
func (d *Devops) EXP_ExecuteWithBinding(ctx context.Context, executeWithBinding *pb.ExecuteWithBinding) (*pb.Response, error) {

	if d.isSecurityEnabled {
		devopsLogger.Debug("Getting TxHandler for binding")

		txHandler, err := d.bindingMap.getTxHandlerForBinding(executeWithBinding.Binding)

		if nil != err {
			return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte(err.Error())}, nil
		}

		ctorbytes, merr := asn1.Marshal(*executeWithBinding.ChaincodeInvocationSpec.ChaincodeSpec.CtorMsg)
		if merr != nil {
			return nil, fmt.Errorf("Error marshalling constructor: %s", err)
		}
		tid, generr := util.GenerateIDWithAlg("", ctorbytes)
		if generr != nil {
			return nil, fmt.Errorf("Error: cannot generate TX ID (executing with binding)")
		}

		tx, err := txHandler.NewChaincodeExecute(executeWithBinding.ChaincodeInvocationSpec, tid)
		if err != nil {
			return nil, fmt.Errorf("Error creating executing with binding:  %s", err)
		}

		return d.coord.ExecuteTransaction(tx), nil
		//return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte("NOT IMPLEMENTED")}, nil

		//return &pb.Response{Status: pb.Response_SUCCESS, Msg: sigmaOutputBytes}, nil
	}
	devopsLogger.Warning("Security NOT enabled")
	return &pb.Response{Status: pb.Response_FAILURE, Msg: []byte("Security NOT enabled")}, nil
}
