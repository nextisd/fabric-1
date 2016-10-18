FROM hyperledger/fabric-peer:latest
# setup the chaincode sample 1)체인코드 샘플 02를 설치 후 빌드 
WORKDIR $GOPATH/src/github.com/hyperledger/fabric/examples/chaincode/go/chaincode_example02
RUN go build
# build the node SDK : 2)node SDK 빌드
WORKDIR $GOPATH/src/github.com/hyperledger/fabric/sdk/node
RUN make all
# now switch to the sample node app location when the shell is opened in the docker 3) docker안에서 쉘이 오픈될 때, 샘플 노드 앱의 경로를 바꾼다.
WORKDIR $GOPATH/src/github.com/hyperledger/fabric/examples/sdk/node
# install the hfc locally for use by the application 4) hfc를 로컬에 인스톨. 
RUN npm install $GOPATH/src/github.com/hyperledger/fabric/sdk/node
