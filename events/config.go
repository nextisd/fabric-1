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

package events

import (
	"flag"
	"fmt"
	"runtime"
	"strings"

	"github.com/op/go-logging"
	"github.com/spf13/viper"
)

// Config the config wrapper structure
type Config struct {
}

// SetupTestLogging setup the logging during test execution
func SetupTestLogging() {
	level, err := logging.LogLevel(viper.GetString("peer.logging.level"))
	if err == nil {
		// No error, use the setting
		logging.SetLevel(level, "main")
		logging.SetLevel(level, "server")
		logging.SetLevel(level, "peer")
	} else {
		logging.SetLevel(logging.ERROR, "main")
		logging.SetLevel(logging.ERROR, "server")
		logging.SetLevel(logging.ERROR, "peer")
	}
}

// SetupTestConfig setup the config during test execution
//이벤트 허브에 대한 셋업은 peer의 core 컨피그 파일에 저장.
//이 환경 설정 파일의 event서버 클라이언트 환경을 읽어들이고, 이에 따라 연결을 구성.
/*
   events:
          # The address that the Event service will be enabled on the validator
		//@@ 이벤트 서비스 주소.
          address: 0.0.0.0:7053

          # total number of events that could be buffered without blocking the
          # validator sends
		//@@ 한번에 송출될 수 있는 맥시멈 이벤트 수는 100
          buffersize: 100
        //@@이벤트 생성자가 이벤트를 송신할때, 부여되는 타임아웃 조건.
        //@@버퍼가 다 찼을 때(100개) 타임아웃 조건에 따라 해당 버퍼의 이벤트들의 송신 여부가 달라짐
          # milliseconds timeout for producer to send an event.
          # if < 0, if buffer full, unblocks immediately and not send
          # if 0, if buffer full, will block and guarantee the event will be sent out
          # if > 0, if buffer full, blocks till timeout
          timeout: 10
*/
func SetupTestConfig() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.Parse()

	// Now set the configuration file
	viper.SetEnvPrefix("HYPERLEDGER")
	viper.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.SetConfigName("core")       // name of config file (without extension)
	viper.AddConfigPath("./")         // path to look for the config file in
	viper.AddConfigPath("./../peer/") // path to look for the config file in
	err := viper.ReadInConfig()       // Find and read the config file
	if err != nil {                   // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	SetupTestLogging()
}
