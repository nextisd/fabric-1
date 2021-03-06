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

package utils

import (
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
)

// DirMissingOrEmpty checks is a directory is missing or empty
// DirMissingOrEmpty() 디렉토리가 비었는지 누락되었는지 확인
//		IN) path
//		OUT) 정상/이상  이상시 errno
func DirMissingOrEmpty(path string) (bool, error) {
	dirExists, err := DirExists(path)
	if err != nil {
		return false, err
	}
	if !dirExists {
		return true, nil
	}

	dirEmpty, err := DirEmpty(path)
	if err != nil {
		return false, err
	}
	if dirEmpty {
		return true, nil
	}
	return false, nil
}

// DirExists checks if a directory exists
// DirExists() : 디렉토리가 있는지 확인
//		IN) path
//		OUT) 정상/이상	이상시 errno
func DirExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// DirEmpty checks if a directory is empty
// DirEmpty() : 디렉토리가 비워있는지 확인
//		IN) path
//		OUT) 정상/이상	이상시 errno
func DirEmpty(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Readdir(1)
	if err == io.EOF {
		return true, nil
	}
	return false, err
}

// FileMissing checks if a file is missing
// FileMissing() : 파일이 누락되었나 확인
//		IN) path, 파일명
//		OUT) 정상/이상	이상시 errno
func FileMissing(path string, name string) (bool, error) {
	_, err := os.Stat(filepath.Join(path, name))
	if err != nil {
		return true, err
	}
	return false, nil
}

// FilePathMissing returns true if the path is missing, false otherwise.
// FilePathMissing() : 파일이 누락되었나 확인
//		IN) path, 파일명
//		OUT) 정상/이상	정상 리턴시 Path Missing
func FilePathMissing(path string) (bool, error) {
	_, err := os.Stat(path)
	if err != nil {
		return true, err
	}
	return false, nil
}

// DecodeBase64 decodes from Base64
// DecodeBase64() Base64 로부터 복호화
func DecodeBase64(in string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(in)
}

// EncodeBase64 encodes to Base64
// EncodeBase64() Base64로 암호화
func EncodeBase64(in []byte) string {
	return base64.StdEncoding.EncodeToString(in)
}

// IntArrayEquals checks if the arrays of ints are the same
func IntArrayEquals(a []int, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
