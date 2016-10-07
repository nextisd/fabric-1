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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"

	"golang.org/x/net/context"

	"github.com/fsouza/go-dockerclient"
	"github.com/hyperledger/fabric/core/chaincode/platforms"
	cutil "github.com/hyperledger/fabric/core/container/util"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/op/go-logging"
)

// VM implemenation of VM management functionality.
//
// VM 구조체 : VM 관리기능 구현 구조체
// 도커 클라이언트에서 Dockerfile 생성후 image build 처리
// 컨테이너 생성은 도커 호스트쪽에서 하므로 controller.go에서 처리
type VM struct {
	Client *docker.Client
}

// NewVM creates a new VM instance.
// NewVM() : 신규 VM 인스턴스를 생성.
func NewVM() (*VM, error) {
	client, err := cutil.NewDockerClient()
	if err != nil {
		return nil, err
	}
	VM := &VM{Client: client}
	return VM, nil
}

// MustGetlogger() : GetLogger와 유사하나 에러 발생시 panic 발생시킴
var vmLogger = logging.MustGetLogger("container")

// ListImages list the images available
// ListImages() : image list available
func (vm *VM) ListImages(context context.Context) error {
	imgs, err := vm.Client.ListImages(docker.ListImagesOptions{All: false})
	if err != nil {
		return err
	}
	for _, img := range imgs {
		fmt.Println("ID: ", img.ID)
		fmt.Println("RepoTags: ", img.RepoTags)
		fmt.Println("Created: ", img.Created)
		fmt.Println("Size: ", img.Size)
		fmt.Println("VirtualSize: ", img.VirtualSize)
		fmt.Println("ParentId: ", img.ParentID)
	}

	return nil
}

// BuildChaincodeContainer builds the container for the supplied chaincode specification
// BuildChaincodeContainer() : ChaincodeSpec을 인자로 받아 컨테이너를 build함
// 체인코드에서는 이 함수를 호출해서 사용
// BuildChaincodeContainer(spec *pb.ChaincodeSpec)
/*
type ChaincodeSpec struct {
	Type                 ChaincodeSpec_Type   `protobuf:"varint,1,opt,name=type,enum=protos.ChaincodeSpec_Type" json:"type,omitempty"`
	ChaincodeID          *ChaincodeID         `protobuf:"bytes,2,opt,name=chaincodeID" json:"chaincodeID,omitempty"`
	CtorMsg              *ChaincodeInput      `protobuf:"bytes,3,opt,name=ctorMsg" json:"ctorMsg,omitempty"`
	Timeout              int32                `protobuf:"varint,4,opt,name=timeout" json:"timeout,omitempty"`
	SecureContext        string               `protobuf:"bytes,5,opt,name=secureContext" json:"secureContext,omitempty"`
	ConfidentialityLevel ConfidentialityLevel `protobuf:"varint,6,opt,name=confidentialityLevel,enum=protos.ConfidentialityLevel" json:"confidentialityLevel,omitempty"`
	Metadata             []byte               `protobuf:"bytes,7,opt,name=metadata,proto3" json:"metadata,omitempty"`
	Attributes           []string             `protobuf:"bytes,8,rep,name=attributes" json:"attributes,omitempty"`
}
*/
// 	1) GetChaincodePackageBytes(spec) : Dockerfile 생성
// 	2) vm.buildChaincodeContainerUsingDockerfilePackageBytes() : 도커 이미지 생성
func (vm *VM) BuildChaincodeContainer(spec *pb.ChaincodeSpec) ([]byte, error) {
	chaincodePkgBytes, err := GetChaincodePackageBytes(spec)
	if err != nil {
		return nil, fmt.Errorf("Error getting chaincode package bytes: %s", err)
	}
	err = vm.buildChaincodeContainerUsingDockerfilePackageBytes(spec, chaincodePkgBytes)
	if err != nil {
		return nil, fmt.Errorf("Error building Chaincode container: %s", err)
	}
	return chaincodePkgBytes, nil
}

// GetChaincodePackageBytes creates bytes for docker container generation using the supplied chaincode specification
// GetChaincodePackageBytes() : ChaincodeSpec을 인자로 받아서 도커 컨테이너 생성을 위한 데이터 들을 패키징(Dockerfile 생성)
func GetChaincodePackageBytes(spec *pb.ChaincodeSpec) ([]byte, error) {
	if spec == nil || spec.ChaincodeID == nil {
		return nil, fmt.Errorf("invalid chaincode spec")
	}

	inputbuf := bytes.NewBuffer(nil)
	gw := gzip.NewWriter(inputbuf)
	tw := tar.NewWriter(gw)

	// 플랫폼 체크 : golang, car, java 가 아니면 에러(현재 기준)
	platform, err := platforms.Find(spec.Type)
	if err != nil {
		return nil, err
	}
	// 플랫폼별 체인코드 패키지 Write
	// 	1.spec.ChaincodeID.Name에 Hash값 세팅
	//	2.dockerFileContents 작성 : chaincode.golang.Dockerfile + "RUN go install %s && cp src/github.com/hyperledger/fabric/peer/core.yaml $GOPATH/bin && mv $GOPATH/bin/%s $GOPATH/bin/%s", urlLocation, chaincodeGoName, spec.ChaincodeID.Name"
	//	3.Dockerfile 생성
	err = platform.WritePackage(spec, tw)
	if err != nil {
		return nil, err
	}

	tw.Close()
	gw.Close()

	if err != nil {
		return nil, err
	}

	chaincodePkgBytes := inputbuf.Bytes()

	return chaincodePkgBytes, nil
}

// Builds the Chaincode image using the supplied Dockerfile package contents
//
// vm.buildChaincodeContainerUsingDockerfilePackageBytes() : Dockerfile 패키지 내용을 사용해서 Chaincode image를 Build
func (vm *VM) buildChaincodeContainerUsingDockerfilePackageBytes(spec *pb.ChaincodeSpec, code []byte) error {
	outputbuf := bytes.NewBuffer(nil)
	vmName := spec.ChaincodeID.Name
	inputbuf := bytes.NewReader(code)
	opts := docker.BuildImageOptions{
		Name:         vmName,
		InputStream:  inputbuf,
		OutputStream: outputbuf,
	}
	if err := vm.Client.BuildImage(opts); err != nil {
		vmLogger.Errorf("Failed Chaincode docker build:\n%s\n", outputbuf.String())
		return err
	}
	return nil
}
