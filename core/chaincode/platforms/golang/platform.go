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
func (goPlatform *Platform) WritePackage(spec *pb.ChaincodeSpec, tw *tar.Writer) error {

	var err error
	spec.ChaincodeID.Name, err = generateHashcode(spec, tw)
	if err != nil {
		return err
	}

	err = writeChaincodePackage(spec, tw)
	if err != nil {
		return err
	}

	return nil
}
