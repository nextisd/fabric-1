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
//@@ cutil.NewDockerClient() 호출
//@@		docker client 생성
//@@		core.yaml 에서 필요한 parameter
//@@		"vm.endpoint" , "vm.docker.tls.enabled"
//@@		vm.docker.tls.enabled = true
//@@		--> "vm.docker.tls.cert.file" / "vm.docker.tls.key.file" / "vm.docker.tls.ca.file"
//@@ docker client 를 가진 VM 생성하여 리턴
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
func (vm *VM) BuildChaincodeContainer(spec *pb.ChaincodeSpec) ([]byte, error) {
	//@@ platform.WritePackage() 호출
	//@@		1.spec.ChaincodeID.Name에 Hash값 세팅
	//@@		2.dockerFileContents 작성 : chaincode.golang.Dockerfile +
	//@@			"RUN go install %s && cp src/github.com/hyperledger/fabric/peer/core.yaml $GOPATH/bin
	//@@			 && mv $GOPATH/bin/%s $GOPATH/bin/%s",
	//@@			urlLocation, chaincodeGoName, spec.ChaincodeID.Name"
	//@@		3.Dockerfile 생성
	//@@ platform.WritePackage(spec, tw) 호출
	//@@		generateHashcode() 호출
	//@@			codegopath 를 구함 ( path 처음이 "http://" 또는 "https://" 경우 ishttp = true )
	//@@ 			ishttp == true 인 경우, getCodeFromHTTP() 호출
	//@@					$GOPATH/_usercode_/임시디렉토리 리턴
	//@@ 			ishttp != true 인 경우, getCodeFromFS() 호출
	//@@					$GOPATH 의 첫번째 path 리턴
	//@@			codegopath/src/path 존재여부 체크 ( path 에서 http:// 등은 제외 )
	//@@			util.GenerateHashFromSignature() 호출
	//@@				sha3.ShakeSum256(ctorbytes) 호출 : ctorbytes 의 hash 리턴
	//@@			hashFilesInDir() 호출
	//@@				rootDir/dir 아래에 있는 모든 file 에 대해 다음 수행
	//@@					directory 면, 그 안에 있는 파일에 대해 recursive 하게 수행
	//@@					file 이면, 읽어서 hash 를 구함 ( hash 는 파일마다 새로 계산 )
	//@@				마지막 hash 리턴
	//@@			hash hex string 리턴  (spec.ChaincodeID.Name 으로 세팅)
	//@@		writeChaincodePackage() 호출
	//@@			chaincode path 에서 마지막 디렉토리 이름이 chaincodeGoName
	//@@			dockerfile 에 추가
	//@@				"RUN go install <urlLocation> && "
	//@@				"cp src/github.com/hyperledger/fabric/peer/core.yaml $GOPATH/bin && "
	//@@				"mv $GOPATH/bin/<chaincodeGoName> $GOPATH/bin/<spec.ChaincodeID.Name>"
	//@@			core.yaml 에 "peer.tls.enabled = true" 면, 아래 추가
	//@@			"COPY src/certs/cert.pem <"peer.tls.cert.file">"
	//@@			dockerfile 에는 core.yaml 에 있는 "chaincode.golang.Dockerfile" 의 내용을 먼저 write
	//@@			tar 파일에 Dockerfile 추가
	//@@			cutil.WriteGopathSrc() 호출
	//@@				WriteFolderToTarPackage() 호출
	//@@					rootDirectory : $GOPATH/src, urlLocation (http:// 제외한 path) 제외
	//@@					대상 파일 : "*.c", "*.h", "*.go", "*.yaml", "*.json"
	//@@				viper.GetBool("peer.tls.enabled") == true 인 경우
	//@@					peer 의 TLS Cert 를 tar 에 추가 ( core.yaml "peer.tls.cert.file" )
	//@@			err 리턴 (정상일 경우, nil)
	//@@		err 리턴 (정상일 경우, nil)
	//@@ tar file 을 []byte 로 리턴
	chaincodePkgBytes, err := GetChaincodePackageBytes(spec)
	if err != nil {
		return nil, fmt.Errorf("Error getting chaincode package bytes: %s", err)
	}
	
	//@@ Image Build Option 생성
	//@@ BuildImage() 호출
	//@@		docker HTTP 에 Image 생성 요청송신/응답처리
	//@@ err 리턴 (정상일 경우, nil)
	err = vm.buildChaincodeContainerUsingDockerfilePackageBytes(spec, chaincodePkgBytes)
	if err != nil {
		return nil, fmt.Errorf("Error building Chaincode container: %s", err)
	}
	return chaincodePkgBytes, nil
}

// GetChaincodePackageBytes creates bytes for docker container generation using the supplied chaincode specification
// GetChaincodePackageBytes() : ChaincodeSpec을 인자로 받아서 도커 컨테이너 생성을 위한 데이터 들을 패키징(Dockerfile 생성)
//@@ platform.WritePackage() 호출
//@@		1.spec.ChaincodeID.Name에 Hash값 세팅
//@@		2.dockerFileContents 작성 : chaincode.golang.Dockerfile +
//@@			"RUN go install %s && cp src/github.com/hyperledger/fabric/peer/core.yaml $GOPATH/bin
//@@			 && mv $GOPATH/bin/%s $GOPATH/bin/%s",
//@@			urlLocation, chaincodeGoName, spec.ChaincodeID.Name"
//@@		3.Dockerfile 생성
//@@ platform.WritePackage(spec, tw) 호출
//@@		generateHashcode() 호출
//@@			codegopath 를 구함 ( path 처음이 "http://" 또는 "https://" 경우 ishttp = true )
//@@ 			ishttp == true 인 경우, getCodeFromHTTP() 호출
//@@					$GOPATH/_usercode_/임시디렉토리 리턴
//@@ 			ishttp != true 인 경우, getCodeFromFS() 호출
//@@					$GOPATH 의 첫번째 path 리턴
//@@			codegopath/src/path 존재여부 체크 ( path 에서 http:// 등은 제외 )
//@@			util.GenerateHashFromSignature() 호출
//@@				sha3.ShakeSum256(ctorbytes) 호출 : ctorbytes 의 hash 리턴
//@@			hashFilesInDir() 호출
//@@				rootDir/dir 아래에 있는 모든 file 에 대해 다음 수행
//@@					directory 면, 그 안에 있는 파일에 대해 recursive 하게 수행
//@@					file 이면, 읽어서 hash 를 구함 ( hash 는 파일마다 새로 계산 )
//@@				마지막 hash 리턴
//@@			hash hex string 리턴  (spec.ChaincodeID.Name 으로 세팅)
//@@		writeChaincodePackage() 호출
//@@			chaincode path 에서 마지막 디렉토리 이름이 chaincodeGoName
//@@			dockerfile 에 추가
//@@				"RUN go install <urlLocation> && "
//@@				"cp src/github.com/hyperledger/fabric/peer/core.yaml $GOPATH/bin && "
//@@				"mv $GOPATH/bin/<chaincodeGoName> $GOPATH/bin/<spec.ChaincodeID.Name>"
//@@			core.yaml 에 "peer.tls.enabled = true" 면, 아래 추가
//@@			"COPY src/certs/cert.pem <"peer.tls.cert.file">"
//@@			dockerfile 에는 core.yaml 에 있는 "chaincode.golang.Dockerfile" 의 내용을 먼저 write
//@@			tar 파일에 Dockerfile 추가
//@@			cutil.WriteGopathSrc() 호출
//@@				WriteFolderToTarPackage() 호출
//@@					rootDirectory : $GOPATH/src, urlLocation (http:// 제외한 path) 제외
//@@					대상 파일 : "*.c", "*.h", "*.go", "*.yaml", "*.json"
//@@				viper.GetBool("peer.tls.enabled") == true 인 경우
//@@					peer 의 TLS Cert 를 tar 에 추가 ( core.yaml "peer.tls.cert.file" )
//@@			err 리턴 (정상일 경우, nil)
//@@		err 리턴 (정상일 경우, nil)
//@@ tar file 을 []byte 로 리턴
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
	//	3.tar file 생성 (Docerfile + src)
	//@@ generateHashcode() 호출
	//@@		codegopath 를 구함 ( path 처음이 "http://" 또는 "https://" 경우 ishttp = true )
	//@@ 		ishttp == true 인 경우, getCodeFromHTTP() 호출
	//@@				$GOPATH/_usercode_/임시디렉토리 리턴
	//@@ 		ishttp != true 인 경우, getCodeFromFS() 호출
	//@@				$GOPATH 의 첫번째 path 리턴
	//@@		codegopath/src/path 존재여부 체크 ( path 에서 http:// 등은 제외 )
	//@@		util.GenerateHashFromSignature() 호출
	//@@			sha3.ShakeSum256(ctorbytes) 호출 : ctorbytes 의 hash 리턴
	//@@		hashFilesInDir() 호출
	//@@			rootDir/dir 아래에 있는 모든 file 에 대해 다음 수행
	//@@				directory 면, 그 안에 있는 파일에 대해 recursive 하게 수행
	//@@				file 이면, 읽어서 hash 를 구함 ( hash 는 파일마다 새로 계산 )
	//@@			마지막 hash 리턴
	//@@		hash hex string 리턴  (spec.ChaincodeID.Name 으로 세팅)
	//@@ writeChaincodePackage() 호출
	//@@		chaincode path 에서 마지막 디렉토리 이름이 chaincodeGoName
	//@@		dockerfile 에 추가
	//@@			"RUN go install <urlLocation> && "
	//@@			"cp src/github.com/hyperledger/fabric/peer/core.yaml $GOPATH/bin && "
	//@@			"mv $GOPATH/bin/<chaincodeGoName> $GOPATH/bin/<spec.ChaincodeID.Name>"
	//@@		core.yaml 에 "peer.tls.enabled = true" 면, 아래 추가
	//@@		"COPY src/certs/cert.pem <"peer.tls.cert.file">"
	//@@		dockerfile 에는 core.yaml 에 있는 "chaincode.golang.Dockerfile" 의 내용을 먼저 write
	//@@		tar 파일에 Dockerfile 추가
	//@@		cutil.WriteGopathSrc() 호출
	//@@			WriteFolderToTarPackage() 호출
	//@@				rootDirectory : $GOPATH/src, urlLocation (http:// 제외한 path) 제외
	//@@				대상 파일 : "*.c", "*.h", "*.go", "*.yaml", "*.json"
	//@@			viper.GetBool("peer.tls.enabled") == true 인 경우
	//@@				peer 의 TLS Cert 를 tar 에 추가 ( core.yaml "peer.tls.cert.file" )
	//@@		err 리턴 (정상일 경우, nil)
	//@@ err 리턴 (정상일 경우, nil)
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
//@@ Image Build Option 생성
//@@ BuildImage() 호출
//@@		docker HTTP 에 Image 생성 요청송신/응답처리
//@@ err 리턴 (정상일 경우, nil)
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
