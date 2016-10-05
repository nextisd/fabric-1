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

package node

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"syscall"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hyperledger/fabric/core/db"
	"github.com/hyperledger/fabric/core/peer"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/net/context"
)

func stopCmd() *cobra.Command {
	nodeStopCmd.Flags().StringVar(&stopPidFile, "stop-peer-pid-file",
		viper.GetString("peer.fileSystemPath"),
		"Location of peer pid local file, for forces kill")

	return nodeStopCmd
}

var nodeStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stops the running node.",
	Long:  `Stops the running node, disconnecting from the network.`,
	Run: func(cmd *cobra.Command, args []string) {
		stop()
	},
}

//@ peer command 에 "stop" 입력시 실행되는 함수
func stop() (err error) {

	//@ clientConn 생성 : "peer.address" 에 정의된 local peer address 로 grpc client connection 맺고,
	//@                   grpc.ClientConn 생성하여 리턴
	clientConn, err := peer.NewPeerClientConnection()
	if err != nil {
		pidFile := stopPidFile + "/peer.pid"
		//fmt.Printf("Stopping local peer using process pid from %s \n", pidFile)
		logger.Infof("Error trying to connect to local peer: %s", err)
		logger.Infof("Stopping local peer using process pid from %s", pidFile)

		//@ local peer 의 PID 얻기 ( 어딘가에 /peer.pid 파일 있음 )
		pid, ferr := readPid(pidFile)
		if ferr != nil {
			err = fmt.Errorf("Error trying to read pid from %s: %s", pidFile, ferr)
			return
		}

		//@ grpc 연결 실패시, peer 프로세스 종료
		killerr := syscall.Kill(pid, syscall.SIGTERM)
		if killerr != nil {
			err = fmt.Errorf("Error trying to kill -9 pid %d: %s", pid, killerr)
			return
		}
		return nil
	}
	logger.Info("Stopping peer using grpc")
	
	//@ 별도로 생성하는 resource 는 없는거 같음
	//@ 인자를 복사해서 adminClient 구조체 만든후 돌려줌
	//@ 구조체 : adminClient , I/F : AdminClient
	serverClient := pb.NewAdminClient(clientConn)

	//@ local peer 에게 REST 요청 ("/protos.Admin/StopServer") 보내서 받은 응답을 돌려줌
	//@ 근데.. 리턴값과 에러 체크도 안 하네??
	status, err := serverClient.StopServer(context.Background(), &empty.Empty{})

	//@ db 와의 session 종료 ( openchainDB.close() 호출 )
	//@ 실제 내용은 아래와 같다. ( CF : ColumnFamilyHandle )
	//@ openchainDB.BlockchainCF.Destroy()
	//@ openchainDB.StateCF.Destroy()
	//@ openchainDB.StateDeltaCF.Destroy()
	//@ openchainDB.IndexesCF.Destroy()
	//@ openchainDB.PersistCF.Destroy()
	//@ openchainDB.DB.Close()
	db.Stop()
	if err != nil {
		fmt.Println(&pb.ServerStatus{Status: pb.ServerStatus_STOPPED})
		return nil
	}

	err = fmt.Errorf("Connection remain opened, peer process doesn't exit")
	fmt.Println(status)
	return err
}

//@ file 경로를 함수인자로 받아서, 
//@ 파일을 열고, lock 걸고
//@ 첨부터 읽어서 숫자로 바꾼뒤 리턴
func readPid(fileName string) (int, error) {
	fd, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return 0, err
	}
	defer fd.Close()
	if err := syscall.Flock(int(fd.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return 0, fmt.Errorf("can't lock '%s', lock is held", fd.Name())
	}

	if _, err := fd.Seek(0, 0); err != nil {
		return 0, err
	}

	data, err := ioutil.ReadAll(fd)
	if err != nil {
		return 0, err
	}

	pid, err := strconv.Atoi(string(bytes.TrimSpace(data)))
	if err != nil {
		return 0, fmt.Errorf("error parsing pid from %s: %s", fd.Name(), err)
	}

	if err := syscall.Flock(int(fd.Fd()), syscall.LOCK_UN); err != nil {
		return 0, fmt.Errorf("can't release lock '%s', lock is held", fd.Name())
	}

	return pid, nil

}
