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
	"flag"
	"fmt"
	"runtime"
	"strings"

	"github.com/op/go-logging"
	"github.com/spf13/viper"
)

// Config the config wrapper structure
//  .config wrapper 구조체를 설정
type Config struct {
}

func init() {

}

// SetupTestLogging setup the logging during test execution
// SetupTestLogging함수는 테스트 실행 로그를 셋팅
func SetupTestLogging() {
	level, err := logging.LogLevel(viper.GetString("peer.logging.level"))
	if err == nil {
		// No error, use the setting
		// peer.logging.level 설정값 사용
		logging.SetLevel(level, "main")
		logging.SetLevel(level, "server")
		logging.SetLevel(level, "peer")
	} else {
		// peer.logging.level 미존재시 로그레벨을 ERROR로 설정
		vmLogger.Warningf("Log level not recognized '%s', defaulting to %s: %s", viper.GetString("peer.logging.level"), logging.ERROR, err)
		logging.SetLevel(logging.ERROR, "main")
		logging.SetLevel(logging.ERROR, "server")
		logging.SetLevel(logging.ERROR, "peer")
	}
}

// SetupTestConfig setup the config during test execution
// SetupTestConfig함수는 테스트 실행시 사용할 config를 셋팅
func SetupTestConfig() {
	flag.Parse()

	// Now set the configuration file
	// 여기서 configuration file 셋팅
	viper.SetEnvPrefix("CORE")
	viper.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.SetConfigName("core")          // name of config file (without extension)	// 설정파일명 (확장자 제외)
	viper.AddConfigPath("./")            // path to look for the config file in		// 설정파일을 찾을 경로
	viper.AddConfigPath("./../../peer/") // path to look for the config file in		// 설정파일을 찾을 경로
	err := viper.ReadInConfig()          // Find and read the config file				// 경로상의 설정 파일 read
	if err != nil {                      // Handle errors reading the config file		// read 에러시 예외처리
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	SetupTestLogging()

	// Set the number of maxprocs
	// maxprocs 갯수 설정
	var numProcsDesired = viper.GetInt("peer.gomaxprocs")
	vmLogger.Debugf("setting Number of procs to %d, was %d\n", numProcsDesired, runtime.GOMAXPROCS(2))

}
