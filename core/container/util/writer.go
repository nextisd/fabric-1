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

package util

import (
	"archive/tar"
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/op/go-logging"
	"github.com/spf13/viper"
)

var vmLogger = logging.MustGetLogger("container")

var includeFileTypes = map[string]bool{
	".c":    true,
	".h":    true,
	".go":   true,
	".yaml": true,
	".json": true,
}

// These filetypes are excluded while creating the tar package sent to Docker
// Generated .class and other temporary files can be excluded
//
// 이 파일타입은 도커에 전송할 tar package 생성에서 제외됨.
// 생성된 .class 파일과 기타 임시 생성파일들도 제외할수 있음.
var javaExcludeFileTypes = map[string]bool{
	".class": true,
}

//WriteFolderToTarPackage() : 입력경로의 디렉토리를 tar로 묶음
func WriteFolderToTarPackage(tw *tar.Writer, srcPath string, excludeDir string, includeFileTypeMap map[string]bool, excludeFileTypeMap map[string]bool) error {
	rootDirectory := srcPath
	vmLogger.Infof("rootDirectory = %s", rootDirectory)

	//append "/" if necessary
	//필요시 "/" 추가
	if excludeDir != "" && strings.LastIndex(excludeDir, "/") < len(excludeDir)-1 {
		excludeDir = excludeDir + "/"
	}

	rootDirLen := len(rootDirectory)
	walkFn := func(path string, info os.FileInfo, err error) error {

		// If path includes .git, ignore
		// 경로에 .git이 포함되어 있을경우 무시함
		if strings.Contains(path, ".git") {
			return nil
		}

		if info.Mode().IsDir() {
			return nil
		}

		//exclude any files with excludeDir prefix. They should already be in the tar
		//excludeDir prefix가 붙은 파일은 제외
		if excludeDir != "" && strings.Index(path, excludeDir) == rootDirLen+1 {
			//1 for "/"
			return nil
		}
		// Because of scoping we can reference the external rootDirectory variable
		// scoping을 통해서 외부 rootDirectory 변수를 참조할 수 있음
		if len(path[rootDirLen:]) == 0 {
			return nil
		}
		ext := filepath.Ext(path)

		if includeFileTypeMap != nil {
			// we only want 'fileTypes' source files at this point
			// 이 시점에는 'fileTypes' 소스 파일만 필요함
			if _, ok := includeFileTypeMap[ext]; ok != true {
				return nil
			}
		}

		//exclude the given file types
		//지정된 file type들은 제외
		if excludeFileTypeMap != nil {
			if exclude, ok := excludeFileTypeMap[ext]; ok && exclude {
				return nil
			}
		}

		newPath := fmt.Sprintf("src%s", path[rootDirLen:])
		//newPath := path[len(rootDirectory):]

		err = WriteFileToPackage(path, newPath, tw)
		if err != nil {
			return fmt.Errorf("Error writing file to package: %s", err)
		}
		return nil
	}

	if err := filepath.Walk(rootDirectory, walkFn); err != nil {
		vmLogger.Infof("Error walking rootDirectory: %s", err)
		return err
	}
	return nil
}

//WriteGopathSrc tars up files under gopath src
//
//@@ WriteGopathSrc() : $GOPATH/src 경로의 소스 코드들을 tar로 묶음
//@@ WriteFolderToTarPackage() 호출
//@@		rootDirectory : $GOPATH/src, excludeDir 는 제외
//@@		대상 파일 : "*.c", "*.h", "*.go", "*.yaml", "*.json"
//@@ viper.GetBool("peer.tls.enabled") == true 인 경우
//@@		peer 의 TLS Cert 를 tar 에 추가 
func WriteGopathSrc(tw *tar.Writer, excludeDir string) error {
	gopath := os.Getenv("GOPATH")
	// Only take the first element of GOPATH
	gopath = filepath.SplitList(gopath)[0]

	rootDirectory := filepath.Join(gopath, "src")
	vmLogger.Infof("rootDirectory = %s", rootDirectory)

	//@@ rootDirectory : $GOPATH/src, excludeDir 는 제외
	//@@ 대상 파일 : "*.c", "*.h", "*.go", "*.yaml", "*.json"
	if err := WriteFolderToTarPackage(tw, rootDirectory, excludeDir, includeFileTypes, nil); err != nil {
		vmLogger.Errorf("Error writing folder to tar package %s", err)
		return err
	}

	// Add the certificates to tar
	//@@ peer 의 TLS Cert 를 tar 에 추가
	if viper.GetBool("peer.tls.enabled") {
		err := WriteFileToPackage(viper.GetString("peer.tls.cert.file"), "src/certs/cert.pem", tw)
		if err != nil {
			return fmt.Errorf("Error writing cert file to package: %s", err)
		}
	}

	// Write the tar file out
	// tar 파일을 작성
	if err := tw.Close(); err != nil {
		return err
	}
	//ioutil.WriteFile("/tmp/chaincode_deployment.tar", inputbuf.Bytes(), 0644)
	return nil
}

//Package Java project to tar file from the source path
//
//WriteJavaProjectToPackage() : srcPath상의 java project를 tar 파일로 패키징
func WriteJavaProjectToPackage(tw *tar.Writer, srcPath string) error {

	vmLogger.Debugf("Packaging Java project from path %s", srcPath)

	if err := WriteFolderToTarPackage(tw, srcPath, "", nil, javaExcludeFileTypes); err != nil {

		vmLogger.Errorf("Error writing folder to tar package %s", err)
		return err
	}
	// tar 파일을 작성
	if err := tw.Close(); err != nil {
		return err
	}
	return nil

}

//WriteFileToPackage writes a file to the tarball
//
//WriteFileToPackage() : tarball 파일을 작성함
func WriteFileToPackage(localpath string, packagepath string, tw *tar.Writer) error {
	fd, err := os.Open(localpath)
	if err != nil {
		return fmt.Errorf("%s: %s", localpath, err)
	}
	defer fd.Close()

	is := bufio.NewReader(fd)
	return WriteStreamToPackage(is, localpath, packagepath, tw)

}

//WriteStreamToPackage writes bytes (from a file reader) to the tarball
//
//WriteStreamToPackage() : file reader.io 로부터의 byte stream을 tarball에 작성함
func WriteStreamToPackage(is io.Reader, localpath string, packagepath string, tw *tar.Writer) error {
	info, err := os.Stat(localpath)
	if err != nil {
		return fmt.Errorf("%s: %s", localpath, err)
	}
	header, err := tar.FileInfoHeader(info, localpath)
	if err != nil {
		return fmt.Errorf("Error getting FileInfoHeader: %s", err)
	}

	//Let's take the variance out of the tar, make headers identical by using zero time
	//zeroTime을통해 tar 파일의 header정보를 고유하게 생성함.
	oldname := header.Name
	var zeroTime time.Time
	header.AccessTime = zeroTime
	header.ModTime = zeroTime
	header.ChangeTime = zeroTime
	header.Name = packagepath

	if err = tw.WriteHeader(header); err != nil {
		return fmt.Errorf("Error write header for (path: %s, oldname:%s,newname:%s,sz:%d) : %s", localpath, oldname, packagepath, header.Size, err)
	}
	if _, err := io.Copy(tw, is); err != nil {
		return fmt.Errorf("Error copy (path: %s, oldname:%s,newname:%s,sz:%d) : %s", localpath, oldname, packagepath, header.Size, err)
	}

	return nil
}
