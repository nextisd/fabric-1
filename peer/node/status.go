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
	"fmt"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hyperledger/fabric/core/peer"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
)

func statusCmd() *cobra.Command {
	return nodeStatusCmd
}

var nodeStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Returns status of the node.",
	Long:  `Returns the status of the running node.`,
	Run: func(cmd *cobra.Command, args []string) {
		status()
	},
}

//@ peer command 로 "status" 입력시 실행되는 함수
func status() (err error) {
	//@ clientConn 생성 : "peer.address" 에 정의된 local peer address 로 grpc client connection 맺음
	//@ 성공 : 
	//@ 실패 : 에러 리턴
	clientConn, err := peer.NewPeerClientConnection()
	if err != nil {
		logger.Infof("Error trying to connect to local peer: %s", err)
		err = fmt.Errorf("Error trying to connect to local peer: %s", err)
		fmt.Println(&pb.ServerStatus{Status: pb.ServerStatus_UNKNOWN})
		return err
	}

	//@ 별도로 생성하는 resource 는 없는거 같음
	//@ 인자를 복사해서 adminClient 구조체 만든후 돌려줌
	//@ 구조체 : adminClient , I/F : AdminClient
	serverClient := pb.NewAdminClient(clientConn)

	//@ local peer 에게 REST 요청 ("/protos.Admin/GetStatus") 보내서 받은 응답을 돌려줌
	status, err := serverClient.GetStatus(context.Background(), &empty.Empty{})
	if err != nil {
		logger.Infof("Error trying to get status from local peer: %s", err)
		err = fmt.Errorf("Error trying to connect to local peer: %s", err)
		fmt.Println(&pb.ServerStatus{Status: pb.ServerStatus_UNKNOWN})
		return err
	}
	fmt.Println(status)
	return nil
}
