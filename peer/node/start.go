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

package node

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/hyperledger/fabric/consensus/helper"
	"github.com/hyperledger/fabric/core"
	"github.com/hyperledger/fabric/core/chaincode"
	"github.com/hyperledger/fabric/core/comm"
	"github.com/hyperledger/fabric/core/crypto"
	"github.com/hyperledger/fabric/core/db"
	"github.com/hyperledger/fabric/core/ledger/genesis"
	"github.com/hyperledger/fabric/core/peer"
	"github.com/hyperledger/fabric/core/rest"
	"github.com/hyperledger/fabric/core/system_chaincode"
	"github.com/hyperledger/fabric/events/producer"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"
)

var chaincodeDevMode bool

func startCmd() *cobra.Command {
	// Set the flags on the node start command.
	flags := nodeStartCmd.Flags()
	flags.BoolVarP(&chaincodeDevMode, "peer-chaincodedev", "", false,
		"Whether peer in chaincode development mode")

	return nodeStartCmd
}

var nodeStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Starts the node.",
	Long:  `Starts a node that interacts with the network.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return serve(args)
	},
}

//@@ peer command 로 "start" 입력시 실행되는 함수
func serve(args []string) error {
	// Parameter overrides must be processed before any paramaters are
	// cached. Failures to cache cause the server to terminate immediately.
	//@@ 모든 파라미터는 cache 되기전에 override 되어야 함
	//@@ cache 실패시 서버는 즉시 종료되어야 함
	if chaincodeDevMode {
		logger.Info("Running in chaincode development mode")
		logger.Info("Set consensus to NOOPS and user starts chaincode")
		logger.Info("Disable loading validity system chaincode")

		viper.Set("peer.validator.enabled", "true")
		viper.Set("peer.validator.consensus", "noops")
		viper.Set("chaincode.mode", chaincode.DevModeUserRunsChaincode)

	}

	//@@ 기본적인 config 변수 값들을 저장
	//@@ string : localAddress, peerEndpoint / bool : securityEnabled
	//@@ int : syncStateSnapshotChannelSize, syncStateDeltasChannelSize, syncBlocksChannelSize, validatorEnabled
	if err := peer.CacheConfiguration(); err != nil {
		return err
	}

	//@@ cache 된 설정에서, peerEndpoint 생성후 리턴 (protos/fabric.pb.go 참조)
	//@@ PeerEndpoint struct : PeerID, Address, Type --> 이건.. msg 임
	peerEndpoint, err := peer.GetPeerEndpoint()
	if err != nil {
		err = fmt.Errorf("Failed to get Peer Endpoint: %s", err)
		return err
	}

	//@@ listen address 얻기 ( core.yaml 에서, listenAddress 찾아봐라 )
	listenAddr := viper.GetString("peer.listenAddress")

	if "" == listenAddr {
		logger.Debug("Listen address not specified, using peer endpoint address")
		listenAddr = peerEndpoint.Address
	}

	//@@ tcp listen 시작
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		grpclog.Fatalf("Failed to listen: %v", err)
	}

	//@@ validator 일 경우에만 grpc server 생성 ( peer.ValidatorEnabled() == true )
	//@@ listen addr : "peer.validator.events.address"
	ehubLis, ehubGrpcServer, err := createEventHubServer()
	if err != nil {
		grpclog.Fatalf("Failed to create ehub server: %v", err)
	}

	logger.Infof("Security enabled status: %t", core.SecurityEnabled())
	if viper.GetBool("security.privacy") {
		if core.SecurityEnabled() {
			logger.Infof("Privacy enabled status: true")
		} else {
			panic(errors.New("Privacy cannot be enabled as requested because security is disabled"))
		}
	} else {
		logger.Infof("Privacy enabled status: false")
	}

	//@@ Rocks DB 에 접속, 기본 handler 생성 ( core/db/db.go 참조 )
	//@@ openchainDB.open() --> openchainDB 에 handler (BlockchainCF, StateCF, StateDeltaCF, IndexesCF) 있음
	//@@ db, cfHandlers, err := gorocksdb.OpenDbColumnFamilies(opts, dbPath, cfNames, cfOpts)
	db.Start()

	var opts []grpc.ServerOption
	if comm.TLSEnabled() {
		//@@ Server 용 TLS 생성 (TransportAuthenticator)
		//@@ PEM 으로 인코딩된 file 쌍에서 public/private key 를 parsing
		//@@ PEM (Privacy Enhanced Mail) : Binary를 Base64로 인코딩
		creds, err := credentials.NewServerTLSFromFile(viper.GetString("peer.tls.cert.file"),
			viper.GetString("peer.tls.key.file"))

		if err != nil {
			grpclog.Fatalf("Failed to generate credentials %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}

	//@@ gRPC 서버 생성 : 등록된 서비스 없으며, 시작되지 않음 (요청처리 불가)
	grpcServer := grpc.NewServer(opts...)

	//@@ ECA / TCA / TLSCA 와 관련된 보안관련 초기화 (인증서, public/private key 포함)
	secHelper, err := getSecHelper()
	if err != nil {
		return err
	}

	secHelperFunc := func() crypto.Peer {
		return secHelper
	}

	//@@ 
	registerChaincodeSupport(chaincode.DefaultChain, grpcServer, secHelper)

	var peerServer *peer.Impl

	// Create the peerServer
	if peer.ValidatorEnabled() {
		logger.Debug("Running as validating peer - making genesis block if needed")
		
		//@@ 
		makeGenesisError := genesis.MakeGenesis()
		if makeGenesisError != nil {
			return makeGenesisError
		}
		logger.Debugf("Running as validating peer - installing consensus %s",
			viper.GetString("peer.validator.consensus"))

		//@@ 
		peerServer, err = peer.NewPeerWithEngine(secHelperFunc, helper.GetEngine)
	} else {
		logger.Debug("Running as non-validating peer")
		peerServer, err = peer.NewPeerWithHandler(secHelperFunc, peer.NewPeerHandler)
	}

	if err != nil {
		logger.Fatalf("Failed creating new peer with handler %v", err)

		return err
	}

	// Register the Peer server
	//@@ 
	pb.RegisterPeerServer(grpcServer, peerServer)

	// Register the Admin server
	//@@ 
	pb.RegisterAdminServer(grpcServer, core.NewAdminServer())

	// Register Devops server
	//@@ 
	serverDevops := core.NewDevopsServer(peerServer)
	pb.RegisterDevopsServer(grpcServer, serverDevops)

	// Register the ServerOpenchain server
	//@@ 
	serverOpenchain, err := rest.NewOpenchainServerWithPeerInfo(peerServer)
	if err != nil {
		err = fmt.Errorf("Error creating OpenchainServer: %s", err)
		return err
	}

	//@@ 
	pb.RegisterOpenchainServer(grpcServer, serverOpenchain)

	// Create and register the REST service if configured
	//@@ 
	if viper.GetBool("rest.enabled") {
		go rest.StartOpenchainRESTServer(serverOpenchain, serverDevops)
	}

	logger.Infof("Starting peer with ID=%s, network ID=%s, address=%s, rootnodes=%v, validator=%v",
		peerEndpoint.ID, viper.GetString("peer.networkId"), peerEndpoint.Address,
		viper.GetString("peer.discovery.rootnode"), peer.ValidatorEnabled())

	// Start the grpc server. Done in a goroutine so we can deploy the
	// genesis block if needed.
	serve := make(chan error)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	//@@ 
	go func() {
		sig := <-sigs
		fmt.Println()
		fmt.Println(sig)
		serve <- nil
	}()

	//@@ 
	go func() {
		var grpcErr error
		if grpcErr = grpcServer.Serve(lis); grpcErr != nil {
			grpcErr = fmt.Errorf("grpc server exited with error: %s", grpcErr)
		} else {
			logger.Info("grpc server exited")
		}
		serve <- grpcErr
	}()

	//@@ 
	if err := writePid(viper.GetString("peer.fileSystemPath")+"/peer.pid", os.Getpid()); err != nil {
		return err
	}

	// Start the event hub server
	//@@ 
	if ehubGrpcServer != nil && ehubLis != nil {
		go ehubGrpcServer.Serve(ehubLis)
	}

	if viper.GetBool("peer.profile.enabled") {
		go func() {
			profileListenAddress := viper.GetString("peer.profile.listenAddress")
			logger.Infof("Starting profiling server with listenAddress = %s", profileListenAddress)
			if profileErr := http.ListenAndServe(profileListenAddress, nil); profileErr != nil {
				logger.Errorf("Error starting profiler: %s", profileErr)
			}
		}()
	}

	// Block until grpc server exits
	//@@ 
	return <-serve
}

//@@  
func registerChaincodeSupport(chainname chaincode.ChainName, grpcServer *grpc.Server,
	secHelper crypto.Peer) {

	//get user mode
	userRunsCC := false
	if viper.GetString("chaincode.mode") == chaincode.DevModeUserRunsChaincode {
		userRunsCC = true
	}

	//get chaincode startup timeout
	//@@ 
	tOut, err := strconv.Atoi(viper.GetString("chaincode.startuptimeout"))
	if err != nil { //what went wrong ?
		fmt.Printf("could not retrive timeout var...setting to 5secs\n")
		tOut = 5000
	}
	ccStartupTimeout := time.Duration(tOut) * time.Millisecond

	//@@ 
	ccSrv := chaincode.NewChaincodeSupport(chainname, peer.GetPeerEndpoint, userRunsCC,
		ccStartupTimeout, secHelper)

	//Now that chaincode is initialized, register all system chaincodes.
	//@@ 
	system_chaincode.RegisterSysCCs()

	//@@ 
	pb.RegisterChaincodeSupportServer(grpcServer, ccSrv)
}

//@@ validator 일 경우에만 grpc server 생성 ( peer.ValidatorEnabled() == true )
//@@ listen addr : "peer.validator.events.address"
func createEventHubServer() (net.Listener, *grpc.Server, error) {
	var lis net.Listener
	var grpcServer *grpc.Server
	var err error

	//@@ node 가 validator 일 경우
	if peer.ValidatorEnabled() {
		// core.yaml "peer.validator.events.address" 에 지정된 address listen
		lis, err = net.Listen("tcp", viper.GetString("peer.validator.events.address"))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to listen: %v", err)
		}

		//TODO - do we need different SSL material for events ?
		//@@ 
		var opts []grpc.ServerOption
		if comm.TLSEnabled() {
			//@@ Server 용 TLS 생성
			creds, err := credentials.NewServerTLSFromFile(
				viper.GetString("peer.tls.cert.file"),
				viper.GetString("peer.tls.key.file"))

			if err != nil {
				return nil, nil, fmt.Errorf("Failed to generate credentials %v", err)
			}
			opts = []grpc.ServerOption{grpc.Creds(creds)}
		}

		//@@ 
		grpcServer = grpc.NewServer(opts...)
		//@@ 
		ehServer := producer.NewEventsServer(
			uint(viper.GetInt("peer.validator.events.buffersize")),
			viper.GetInt("peer.validator.events.timeout"))

		//@@ 
		pb.RegisterEventsServer(grpcServer, ehServer)
	}
	return lis, grpcServer, err
}

//@@ filename 의 file 생성 (path 포함)
//@@ 자신의 pid 기록 (lock 처리)
func writePid(fileName string, pid int) error {
	//@@ 모든 경로 생성
	err := os.MkdirAll(filepath.Dir(fileName), 0755)
	if err != nil {
		return err
	}

	//@@ file open
	fd, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer fd.Close()

	//@@ file lock
	if err := syscall.Flock(int(fd.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("can't lock '%s', lock is held", fd.Name())
	}

	if _, err := fd.Seek(0, 0); err != nil {
		return err
	}

	if err := fd.Truncate(0); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(fd, "%d", pid); err != nil {
		return err
	}

	if err := fd.Sync(); err != nil {
		return err
	}

	//@@ file unlock
	if err := syscall.Flock(int(fd.Fd()), syscall.LOCK_UN); err != nil {
		return fmt.Errorf("can't release lock '%s', lock is held", fd.Name())
	}
	return nil
}

var once sync.Once

//this should be called exactly once and the result cached
//NOTE- this crypto func might rightly belong in a crypto package
//and universally accessed
//@@ 정확히 1번 불려져야 하며, 결과는 cache 됨 --> 내부에 once 처리됨
//@@ enrollID : config 값 "security.enrollID" ( core.yaml -> security: --> enrollID: )
//@@ enrollSecret : config 값 "security.enrollSecret" ( core.yaml -> security: --> enrollSecret: )
//@@ if validator : crypto.RegisterValidator() --> crypto.InitValidator()
//@@ else (peer)  : crypto.RegisterPeer()      --> crypto.InitPeer()
//@@ crypto.RegisterValidator() , crypto.RegisterPeer() : enrollID 를 PKI 인프라 (ECA, TCA) 에 등록
//@@                                                      실제로는 ECA/TCA/TLSCA 인증서 받아서 key-storage 에 저장..
func getSecHelper() (crypto.Peer, error) {
	var secHelper crypto.Peer
	var err error
	//@@ 
	once.Do(func() {
		if core.SecurityEnabled() {
			enrollID := viper.GetString("security.enrollID")
			enrollSecret := viper.GetString("security.enrollSecret")

			//@@ node Type == validator
			if peer.ValidatorEnabled() {
				logger.Debugf("Registering validator with enroll ID: %s", enrollID)
				//@@ enrollID 를 PKI 인프라 (ECA, TCA) 에 등록
				//@@ 실제로는 ECA/TCA/TLSCA 인증서 받아서 key-storage 에 저장..
				if err = crypto.RegisterValidator(enrollID, nil, enrollID, enrollSecret); nil != err {
					return
				}
				logger.Debugf("Initializing validator with enroll ID: %s", enrollID)

				//@@ ECA / TCA / TLSCA 인증서 load
				//@@ public / private key load
				secHelper, err = crypto.InitValidator(enrollID, nil)
				if nil != err {
					return
				}
			//@@ node Type != validator
			} else {
				logger.Debugf("Registering non-validator with enroll ID: %s", enrollID)
				//@@ enrollID 를 PKI 인프라 (ECA, TCA) 에 등록
				//@@ 실제로는 ECA/TCA/TLSCA 인증서 받아서 key-storage 에 저장..
				if err = crypto.RegisterPeer(enrollID, nil, enrollID, enrollSecret); nil != err {
					return
				}
				logger.Debugf("Initializing non-validator with enroll ID: %s", enrollID)

				//@@ ECA / TCA / TLSCA 인증서 load
				//@@ public / private key load
				secHelper, err = crypto.InitPeer(enrollID, nil)
				if nil != err {
					return
				}
			}
		}
	})
	return secHelper, err
}
