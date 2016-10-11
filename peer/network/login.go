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

package network

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/howeyc/gopass"
	"github.com/hyperledger/fabric/core/peer"
	"github.com/hyperledger/fabric/peer/common"
	"github.com/hyperledger/fabric/peer/util"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
)

func loginCmd() *cobra.Command {
	// Set the flags on the login command.
	networkLoginCmd.PersistentFlags().StringVarP(&loginPW, "password", "p",
		common.UndefinedParamValue,
		"The password for user. You will be requested to enter the password if "+
			"this flag is not specified.")

	return networkLoginCmd
}

//@@ "peer network login <username>" 실행하면, networkLogin() 실행
var networkLoginCmd = &cobra.Command{
	Use:   "login <username>",
	Short: "Logs in user to CLI.",
	Long:  `Logs in the local user to CLI. Must supply username as a parameter.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return networkLogin(args)
	},
}

// login related variables.
var (
	loginPW string
)

// login confirms the enrollmentID and secret password of the client with the
// CA and stores the enrollment certificate and key in the Devops server.
//@@ login 은 CA 와 client 의 (enrollment ID, secret password) 를 확인하고
//@@ ECert 와 Key 를 Devops 서버에 보관
func networkLogin(args []string) error {
	logger.Info("CLI client login...")

	// Check for username argument
	if len(args) == 0 {
		return errors.New("Must supply username")
	}

	// Check for other extraneous arguments
	if len(args) != 1 {
		return errors.New("Must supply username as the 1st and only parameter")
	}

	// Retrieve the CLI data storage path
	// Returns /var/openchain/production/client/
	//@@ client login token 을 보관하는 local path 를 얻기위한 helper function.
	//@@ path : "peer.fileSystemPath" (core.yaml) + "/client/"
	localStore := util.GetCliFilePath()
	logger.Infof("Local data store for client loginToken: %s", localStore)

	// If the user is already logged in, return
	//@@ file 유무 체크 : "peer.fileSystemPath" (core.yaml) + "/client/" + username
	//@@ 있다면, 이미 로그인했다는 것... 에러 리턴
	if _, err := os.Stat(localStore + "loginToken_" + args[0]); err == nil {
		logger.Infof("User '%s' is already logged in.\n", args[0])
		return err
	}

	// If the '--password' flag is not specified, need read it from the terminal
	//@@ --password 또는 -p flag 가 없다면, 터미널로부터 password 읽기
	if loginPW == "" {
		// User is not logged in, prompt for password
		fmt.Printf("Enter password for user '%s': ", args[0])
		//@@ 사용자가 입력하는 password 읽음 ( 화면에는 password 가 * 로 표시 )
		pw, err := gopass.GetPasswdMasked()
		if err != nil {
			return fmt.Errorf("Error trying to read password from console: %s", err)
		}

		loginPW = string(pw)
	}

	// Log in the user
	logger.Infof("Logging in user '%s' on CLI interface...\n", args[0])

	// Get a devopsClient to perform the login
	//@@ clientConn 생성 : "peer.address" 에 정의된 local peer address 로 grpc client connection 맺고,
	//@@                   grpc.ClientConn 생성하여 리턴
	clientConn, err := peer.NewPeerClientConnection()
	if err != nil {
		return fmt.Errorf("Error trying to connect to local peer: %s", err)
	}
	//@@ GetDevopsClient peer 의 새로운 client connection 을 리턴
	//@@ see "github.com/hyperledger/fabric/protos" NewDevopsClient()
	devopsClient := pb.NewDevopsClient(clientConn)

	// Build the login spec and login
	loginSpec := &pb.Secret{EnrollId: args[0], EnrollSecret: loginPW}
	//@@ see "github.com/hyperledger/fabric/core/devops.go" Login()
	//@@ 내부에서 core/crypto/client.go:RegisterClient() 호출
	//@@ core/crypto/client.go:RegisterClient() : Client 를 PKI 에 등록
	loginResult, err := devopsClient.Login(context.Background(), loginSpec)

	// Check if login is successful
	if loginResult.Status == pb.Response_SUCCESS {
		// If /var/openchain/production/client/ directory does not exist, create it
		if _, err := os.Stat(localStore); err != nil {
			if os.IsNotExist(err) {
				// Directory does not exist, create it
				if err := os.Mkdir(localStore, 0755); err != nil {
					panic(fmt.Errorf("Fatal error when creating %s directory: %s\n", localStore, err))
				}
			} else {
				// Unexpected error
				panic(fmt.Errorf("Fatal error on os.Stat of %s directory: %s\n", localStore, err))
			}
		}

		// Store client security context into a file
		logger.Infof("Storing login token for user '%s'.\n", args[0])
		err = ioutil.WriteFile(localStore+"loginToken_"+args[0], []byte(args[0]), 0755)
		if err != nil {
			panic(fmt.Errorf("Fatal error when storing client login token: %s\n", err))
		}

		logger.Infof("Login successful for user '%s'.\n", args[0])
	} else {
		return fmt.Errorf("Error on client login: %s", string(loginResult.Msg))
	}

	return nil
}
