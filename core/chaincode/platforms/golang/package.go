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
	"strings"
	"time"

	"github.com/spf13/viper"

	cutil "github.com/hyperledger/fabric/core/container/util"
	pb "github.com/hyperledger/fabric/protos"
)

//tw is expected to have the chaincode in it from GenerateHashcode. This method
//will just package rest of the bytes
//@@ dockerfile && tar file 에 write 함
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
func writeChaincodePackage(spec *pb.ChaincodeSpec, tw *tar.Writer) error {

	var urlLocation string
	if strings.HasPrefix(spec.ChaincodeID.Path, "http://") {
		urlLocation = spec.ChaincodeID.Path[7:]
	} else if strings.HasPrefix(spec.ChaincodeID.Path, "https://") {
		urlLocation = spec.ChaincodeID.Path[8:]
	} else {
		urlLocation = spec.ChaincodeID.Path
	}

	if urlLocation == "" {
		return fmt.Errorf("empty url location")
	}

	if strings.LastIndex(urlLocation, "/") == len(urlLocation)-1 {
		urlLocation = urlLocation[:len(urlLocation)-1]
	}
	toks := strings.Split(urlLocation, "/")
	if toks == nil || len(toks) == 0 {
		return fmt.Errorf("cannot get path components from %s", urlLocation)
	}

	chaincodeGoName := toks[len(toks)-1]
	if chaincodeGoName == "" {
		return fmt.Errorf("could not get chaincode name from path %s", urlLocation)
	}

	//let the executable's name be chaincode ID's name
	//@@ dockerfile 에 추가
	//@@		"RUN go install <urlLocation> && "
	//@@		"cp src/github.com/hyperledger/fabric/peer/core.yaml $GOPATH/bin && "
	//@@		"mv $GOPATH/bin/<chaincodeGoName> $GOPATH/bin/<spec.ChaincodeID.Name>"	
	newRunLine := fmt.Sprintf("RUN go install %s && cp src/github.com/hyperledger/fabric/peer/core.yaml $GOPATH/bin && mv $GOPATH/bin/%s $GOPATH/bin/%s", urlLocation, chaincodeGoName, spec.ChaincodeID.Name)

	//NOTE-this could have been abstracted away so we could use it for all platforms in a common manner
	//However, it would still be docker specific. Hence any such abstraction has to be done in a manner that
	//is not just language dependent but also container depenedent. So lets make this change per platform for now
	//in the interest of avoiding over-engineering without proper abstraction
	//@@ core.yaml 에 "peer.tls.enabled = true" 면, 아래 추가
	//@@ "COPY src/certs/cert.pem <"peer.tls.cert.file">"
	if viper.GetBool("peer.tls.enabled") {
		newRunLine = fmt.Sprintf("%s\nCOPY src/certs/cert.pem %s", newRunLine, viper.GetString("peer.tls.cert.file"))
	}

	//@@ dockerfile 에는 core.yaml 에 있는 "chaincode.golang.Dockerfile" 의 내용을 먼저 write
	dockerFileContents := fmt.Sprintf("%s\n%s", cutil.GetDockerfileFromConfig("chaincode.golang.Dockerfile"), newRunLine)
	dockerFileSize := int64(len([]byte(dockerFileContents)))

	//Make headers identical by using zero time
	//@@ tar 파일에 Dockerfile 추가
	var zeroTime time.Time
	tw.WriteHeader(&tar.Header{Name: "Dockerfile", Size: dockerFileSize, ModTime: zeroTime, AccessTime: zeroTime, ChangeTime: zeroTime})
	tw.Write([]byte(dockerFileContents))
	
	//@@ WriteFolderToTarPackage() 호출
	//@@		rootDirectory : $GOPATH/src, urlLocation (http:// 제외한 path) 제외
	//@@		대상 파일 : "*.c", "*.h", "*.go", "*.yaml", "*.json"
	//@@ viper.GetBool("peer.tls.enabled") == true 인 경우
	//@@		peer 의 TLS Cert 를 tar 에 추가 ( core.yaml "peer.tls.cert.file" )
	err := cutil.WriteGopathSrc(tw, urlLocation)
	if err != nil {
		return fmt.Errorf("Error writing Chaincode package contents: %s", err)
	}
	return nil
}
