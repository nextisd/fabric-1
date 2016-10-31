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

package pbft

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hyperledger/fabric/consensus"
	pb "github.com/hyperledger/fabric/protos"

	"github.com/golang/protobuf/proto"
	"github.com/spf13/viper"
)

const configPrefix = "CORE_PBFT"

var pluginInstance consensus.Consenter // singleton service
var config *viper.Viper

func init() {
	config = loadConfig()
}

// GetPlugin returns the handle to the Consenter singleton
//
// GetPlugin() : Consenter 싱글턴 인스턴스 리턴.
// @param c consensus.Stack : 컨센서스 플러그인에서 나머지 컨센서스 스택에 접근할 수 있는 메서드 집합.
//
// @consensus.Stack 인터페이스 정리
//	1. NetworkStack - 네트워크 정보 검색 및 메시지 전송
//		1.1 Communicator - 다른 VP들에게 메시지 전송
//			1.1.1 broadcast()
//			1.1.2 unicast()
//		1.2 Inquirer - Validating N/W 정보 조회
//			1.2.1 GetNetworkInfo()
//			1.2.2 GetNetworkHandles()
//
//	2. SecurityUtils - crypto 패키지의 sign/verify에 액세스
//		2.1 Sign()
//		2.2 Verify()
//
//	3. Executor - 구버전 executor(아래 LegacyExecutor?)를 대체하기 위해 사용
//		Begin/Exec/CommitTxBatch를 다이렉트로 호출하게 되면,
//		state 전송을 통해 race컨디션과 ledger 이상을 방지하는 작업이 반드시 구성되어야 하는 문제가 있음.
//		3.1 Start()
//		3.2 Halt()
//		3.3 Execute()
//		3.4 Commit()
//		3.5 Rollback()
//		3.6 UpdateState()
//
//	4. LegacyExecutor - ledger에 반영될 tx invoke 처리
//		4.1 BeginTxBatch()
//		4.2 ExecTxs()
//		4.3 CommitTxBatch()
//		4.4 RollbackTxBatch()
//		4.5 PreviewCommitTxBatch()
//
//	5. LedgerManager - ledger의 state 상태를 조회(synched?)
//		5.1 InvalidateState() - consensus가 out of sync라는것을 세팅(Helper.valid=false)해서 알려줌.
//		5.2 ValidateState() - consesus가 synched라는것을 세팅(Helper.valid=true)해서 알려줌.
//
//	6. ReadOnlyLedger - 블록체인 조회용
//		6.1 GetBlock()
//		6.2 GetBlockchainSize()
//		6.3 GetBlockchainInfo()
//		6.4 GetBlockchainInfoBlob() - ledger의 BlockchainInfo를 protobuf로 마샬링
//		6.5 GetBlockHeadMetadata()
//
//
// GetPlugin() : Consenter 싱글턴 인스턴스 생성자.
//	 	@param c consensus.Stack : 컨센서스 플러그인에서 나머지 컨센서스 스택에 접근할 수 있는 메서드 집합.
// 		consensus/controller/controller.go - NewConsenter(stack consensus.Stack)에서 호출함.
func GetPlugin(c consensus.Stack) consensus.Consenter {
	if pluginInstance == nil {
		pluginInstance = New(c)
	}
	return pluginInstance
}

// New creates a new Obc* instance that provides the Consenter interface.
// Internally, it uses an opaque pbft-core instance.
//
// New() : Consenter 인터페이스를 가진 인스턴스 생성
// 내부적으로 opaque pbft-core 인스턴스를 사용
// opaque data type? : 해당 데이터 타입의 내부 저보가 외부 인터페이스로 모두 노출되지 않은 데이터 타입.
//                     구조체 내부의 데이터는 외부로 노출된 함수를 통해서만 가능.
func New(stack consensus.Stack) consensus.Consenter {

	// 현재 VP와 전체 네트워크의 VP들의 PeerID를 리턴 - helper.go GetNetworkHandles()
	handle, _, _ := stack.GetNetworkHandles()
	id, _ := getValidatorID(handle)

	switch strings.ToLower(config.GetString("general.mode")) {
	case "batch":
		//
		return newObcBatch(id, config, stack)
	default:
		panic(fmt.Errorf("Invalid PBFT mode: %s", config.GetString("general.mode")))
	}
}

func loadConfig() (config *viper.Viper) {
	config = viper.New()

	// for environment variables
	config.SetEnvPrefix(configPrefix)
	config.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	config.SetEnvKeyReplacer(replacer)

	config.SetConfigName("config")
	config.AddConfigPath("./")
	config.AddConfigPath("../consensus/pbft/")
	config.AddConfigPath("../../consensus/pbft")
	// Path to look for the config file in based on GOPATH
	gopath := os.Getenv("GOPATH")
	for _, p := range filepath.SplitList(gopath) {
		pbftpath := filepath.Join(p, "src/github.com/hyperledger/fabric/consensus/pbft")
		config.AddConfigPath(pbftpath)
	}

	err := config.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Error reading %s plugin config: %s", configPrefix, err))
	}
	return
}

// Returns the uint64 ID corresponding to a peer handle
//
// getValidatorID() : @handle에 해당하는 피어의 uint64 ID 리턴
func getValidatorID(handle *pb.PeerID) (id uint64, err error) {
	// as requested here: https://github.com/hyperledger/fabric/issues/462#issuecomment-170785410
	if startsWith := strings.HasPrefix(handle.Name, "vp"); startsWith {
		id, err = strconv.ParseUint(handle.Name[2:], 10, 64)
		if err != nil {
			return id, fmt.Errorf("Error extracting ID from \"%s\" handle: %v", handle.Name, err)
		}
		return
	}

	err = fmt.Errorf(`For MVP, set the VP's peer.id to vpX,
		where X is a unique integer between 0 and N-1
		(N being the maximum number of VPs in the network`)
	return
}

// Returns the peer handle that corresponds to a validator ID (uint64 assigned to it for PBFT)
//
// getValidatorHandler() : validator ID(PBFT처리를 위한 uint64할당)에 해당하는 peer handle 리턴
func getValidatorHandle(id uint64) (handle *pb.PeerID, err error) {
	// as requested here: https://github.com/hyperledger/fabric/issues/462#issuecomment-170785410

	// "vp" prefix 붙이기
	name := "vp" + strconv.FormatUint(id, 10)
	return &pb.PeerID{Name: name}, nil
}

// Returns the peer handles corresponding to a list of replica ids
//
// getValidatorHandles() : replica id들에 대한 peer handle 리턴
func getValidatorHandles(ids []uint64) (handles []*pb.PeerID) {
	handles = make([]*pb.PeerID, len(ids))
	for i, id := range ids {
		handles[i], _ = getValidatorHandle(id)
	}
	return
}

// NewObcBatch(pbft-batch.go)에서 사용되는 메서드 스택 모음.
// NewConsentor->GetPlugin->New(PBFT)->NewObcBatch 순서로 호출됨
type obcGeneric struct {
	stack consensus.Stack
	pbft  *pbftCore
}

func (op *obcGeneric) skipTo(seqNo uint64, id []byte, replicas []uint64) {
	info := &pb.BlockchainInfo{}
	err := proto.Unmarshal(id, info)
	if err != nil {
		logger.Error(fmt.Sprintf("Error unmarshaling: %s", err))
		return
	}
	op.stack.UpdateState(&checkpointMessage{seqNo, id}, info, getValidatorHandles(replicas))
}

// op.invalidateState() : consensus가 out of sync라는것을 세팅(Helper.valid=false)해서 알려줌.
func (op *obcGeneric) invalidateState() {
	op.stack.InvalidateState()
}

// op.validateState() : consesus가 synched라는것을 세팅(Helper.valid=true)해서 알려줌.
func (op *obcGeneric) validateState() {
	op.stack.ValidateState()
}

// op.GetState() : ledger의 BlockchainInfo를 protobuf로 마샬링.
func (op *obcGeneric) getState() []byte {
	return op.stack.GetBlockchainInfoBlob()
}

// op.getLastSeqNo() : 블록헤드의 Metadata.SeqNo 가져오기
func (op *obcGeneric) getLastSeqNo() (uint64, error) {
	raw, err := op.stack.GetBlockHeadMetadata()
	if err != nil {
		return 0, err
	}
	// Metadata 구조체 : SeqNo uint64 `protobuf:"varint,1,opt,name=seqNo" json:"seqNo,omitempty"`
	meta := &Metadata{}
	proto.Unmarshal(raw, meta)
	return meta.SeqNo, nil
}
