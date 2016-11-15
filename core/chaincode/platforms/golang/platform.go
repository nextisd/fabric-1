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

package golang

import (
	"archive/tar"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	pb "github.com/hyperledger/fabric/protos"
)

// Platform for chaincodes written in Go
// go언어로 작성된 체인코드의 플랫폼
type Platform struct {
}

// Returns whether the given file or directory exists or not
// 입력된 경로가 존재하는지, 해당 경로에 파일이 존재하는지 여부를 체크
func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

// ValidateSpec validates Go chaincodes
// @@ Go 체인코드 스펙을 검증
//@@ URL Parse : String -> URL structure.
//@@ URL 이 아니면 $GOPATH/src 아래에서 path 가 있는지 확인
func (goPlatform *Platform) ValidateSpec(spec *pb.ChaincodeSpec) error {
	url, err := url.Parse(spec.ChaincodeID.Path)
	if err != nil || url == nil {
		return fmt.Errorf("invalid path: %s", err)
	}

	//we have no real good way of checking existence of remote urls except by downloading and testin
	//which we do later anyway. But we *can* - and *should* - test for existence of local paths.
	//Treat empty scheme as a local filesystem path
	if url.Scheme == "" {
		gopath := os.Getenv("GOPATH")
		// Only take the first element of GOPATH
		gopath = filepath.SplitList(gopath)[0]
		pathToCheck := filepath.Join(gopath, "src", spec.ChaincodeID.Path)
		exists, err := pathExists(pathToCheck)
		if err != nil {
			return fmt.Errorf("Error validating chaincode path: %s", err)
		}
		if !exists {
			return fmt.Errorf("Path to chaincode does not exist: %s", spec.ChaincodeID.Path)
		}
	}
	return nil
}

// WritePackage writes the Go chaincode package
// go 언어 체인코드 패키지를 write ( Dockerfile --> *.tar file )
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
func (goPlatform *Platform) WritePackage(spec *pb.ChaincodeSpec, tw *tar.Writer) error {

	var err error
	//@@ codegopath 를 구함 ( path 처음이 "http://" 또는 "https://" 경우 ishttp = true )
	//@@ 	ishttp == true 인 경우, getCodeFromHTTP() 호출
	//@@			$GOPATH/_usercode_/임시디렉토리 리턴
	//@@ 	ishttp != true 인 경우, getCodeFromFS() 호출
	//@@			$GOPATH 의 첫번째 path 리턴
	//@@ codegopath/src/path 존재여부 체크 ( path 에서 http:// 등은 제외 )
	//@@ util.GenerateHashFromSignature() 호출
	//@@		sha3.ShakeSum256(ctorbytes) 호출 : ctorbytes 의 hash 리턴
	//@@ hashFilesInDir() 호출
	//@@		rootDir/dir 아래에 있는 모든 file 에 대해 다음 수행
	//@@			directory 면, 그 안에 있는 파일에 대해 recursive 하게 수행
	//@@			file 이면, 읽어서 hash 를 구함 ( hash 는 파일마다 새로 계산 )
	//@@		마지막 hash 리턴
	//@@ hash hex string 리턴 (spec.ChaincodeID.Name 으로 세팅)
	spec.ChaincodeID.Name, err = generateHashcode(spec, tw)
	if err != nil {
		return err
	}

	//@@ chaincode path 에서 마지막 디렉토리 이름이 chaincodeGoName
	//@@ dockerfile 에 추가
	//@@		"RUN go install <urlLocation> && "
	//@@		"cp src/github.com/hyperledger/fabric/peer/core.yaml $GOPATH/bin && "
	//@@		"mv $GOPATH/bin/<chaincodeGoName> $GOPATH/bin/<spec.ChaincodeID.Name>"
	//@@ core.yaml 에 "peer.tls.enabled = true" 면, 아래 추가
	//@@ "COPY src/certs/cert.pem <"peer.tls.cert.file">"
	//@@ dockerfile 에는 core.yaml 에 있는 "chaincode.golang.Dockerfile" 의 내용을 먼저 write
	//@@ tar 파일에 Dockerfile 추가
	//@@ cutil.WriteGopathSrc() 호출
	//@@		WriteFolderToTarPackage() 호출
	//@@			rootDirectory : $GOPATH/src, urlLocation (http:// 제외한 path) 제외
	//@@			대상 파일 : "*.c", "*.h", "*.go", "*.yaml", "*.json"
	//@@		viper.GetBool("peer.tls.enabled") == true 인 경우
	//@@			peer 의 TLS Cert 를 tar 에 추가 ( core.yaml "peer.tls.cert.file" )
	//@@ err 리턴 (정상일 경우, nil)
	err = writeChaincodePackage(spec, tw)
	if err != nil {
		return err
	}

	return nil
}
