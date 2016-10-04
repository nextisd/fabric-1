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

package config

import (
	"flag"
	"fmt"
	"runtime"
	"strings"

	"github.com/spf13/viper"
)

// Config the config wrapper structure
type Config struct {
}

var configLogger = logging.MustGetLogger("config")

func init() {

}

// SetupTestLogging : 테스트 실행하는 동안 Logging Setup
func SetupTestLogging() {
	level, err := logging.LogLevel(viper.GetString("logging.peer"))
	if err == nil {
		// No error, use the setting
		logging.SetLevel(level, "main")
		logging.SetLevel(level, "server")
		logging.SetLevel(level, "peer")
	} else {
		configLogger.Warningf("Log level not recognized '%s', defaulting to %s: %s", viper.GetString("logging.peer"), logging.ERROR, err)
		logging.SetLevel(logging.ERROR, "main")
		logging.SetLevel(logging.ERROR, "server")
		logging.SetLevel(logging.ERROR, "peer")
	}
}

// SetupTestConfig : 테스트하는 동안 Config 설정
func SetupTestConfig(pathToOpenchainYaml string) {
	flag.Parse()

	// 설정파일 Set
	viper.SetEnvPrefix("HYPERLEDGER")
	viper.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.SetConfigName("core")              // 설정파일명 (without extension)
	viper.AddConfigPath(pathToOpenchainYaml) // 설정파일을 찾을 수 있는 Path
	err := viper.ReadInConfig()              // 설정파일을 찾아서 Read
	if err != nil {                          // Config파일 Read 이상 발생
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	SetupTestLogging()

	// Set the number of maxprocs 최대 Process 수 Set
	var numProcsDesired = viper.GetInt("peer.gomaxprocs")
	configLogger.Debugf("setting Number of procs to %d, was %d\n", numProcsDesired, runtime.GOMAXPROCS(2))

}
