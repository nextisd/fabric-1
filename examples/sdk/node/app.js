/*
 Copyright IBM Corp 2016 All Rights Reserved.

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

/*
 * A simple application utilizing the Node.js Client SDK to:
 * 1) Enroll a user
 * 2) User deploys chaincode
 * 3) User queries chaincode
 */
//@@Node.js를 이용한 간단한 어플리케이션 개발 킷
//@@사용자를 등록
//@@일반 체인코드 배포 및 조회 

// "HFC" stands for "Hyperledger Fabric Client"
//@@ HFC는 Hyperledger Fabric Client를 지칭.
var hfc = require("hfc");

console.log(" **** starting HFC sample ****");


// get the addresses from the docker-compose environment
//@@docker-compose 환경에서 주소 정보를 얻어옴 : 피어 주소, 멤버쉽 서비스 주소
var PEER_ADDRESS         = process.env.CORE_PEER_ADDRESS;
var MEMBERSRVC_ADDRESS   = process.env.MEMBERSRVC_ADDRESS;

var chain, chaincodeID;

// Create a chain object used to interact with the chain.
// You can name it anything you want as it is only used by client.
//@@ 체인 객체를 생성하고 이름을 부여.  
chain = hfc.newChain("mychain");
// Initialize the place to store sensitive private key information
//@@ 개인키 정보를 보관할 스토리지를 셋
chain.setKeyValStore( hfc.newFileKeyValStore('/tmp/keyValStore') );
// Set the URL to membership services and to the peer
//@@ 멤버쉽 서비스와 피어에 접근할 URL을 셋
console.log("member services address ="+MEMBERSRVC_ADDRESS);
console.log("peer address ="+PEER_ADDRESS);
chain.setMemberServicesUrl("grpc://"+MEMBERSRVC_ADDRESS);
chain.addPeer("grpc://"+PEER_ADDRESS);

// The following is required when the peer is started in dev mode
// (i.e. with the '--peer-chaincodedev' option)
//@@ 아래는, 피어가 dev(개발) 모드로 구동되었을 때, 요구되는 사항들
var mode =  process.env['DEPLOY_MODE'];
console.log("DEPLOY_MODE=" + mode);
if (mode === 'dev') {
    chain.setDevMode(true);
    //Deploy will not take long as the chain should already be running
    chain.setDeployWaitTime(10); //체인이 이미 동작하고 있는 상황에서 제한시간 이내(10) 배포가 되어야 함?
} else {
    chain.setDevMode(false);
    //Deploy will take much longer in network mode // 개발모드가 아닐 경우에는, 배포 제한 시간이 120으로 더 길게 잡힘(네트워킹 고려?)
    chain.setDeployWaitTime(120);
}


chain.setInvokeWaitTime(10); //실행 대기 시간 10, 개발모드는 배포 시간에만 관련 있고 실행에 대한 제한 시간은 동일

// Begin by enrolling the user
//@@ 사용자를 등록함으로써, 클라이언트가 시작됨.
enroll();

// Enroll a user. 
//@@ 사용자 등록
function enroll() {
   console.log("enrolling user admin ...");
   // Enroll "admin" which is preregistered in the membersrvc.yaml
   //@@ membersrvc.yaml에 정의된 admin은 미리 등록되어 있음.
   chain.enroll("admin", "Xurw3yU9zI0l", function(err, admin) { 
      if (err) {
         console.log("ERROR: failed to register admin: %s",err);
         process.exit(1);
      }
      // Set this user as the chain's registrar which is authorized to register other users.
	  //@@ 해당 유저를 다른 유저의 등록을 허용하는 권한을 가진 체인의 registrar로 등록. 
      chain.setRegistrar(admin);
      
      var userName = "JohnDoe"; 
      // registrationRequest
	  //@@ 임의의 사용자 등록 요청을 만듬, 사용자 이름은 JohnDoe
      var registrationRequest = {
          enrollmentID: userName,
          affiliation: "bank_a"
      };
      chain.registerAndEnroll(registrationRequest, function(error, user) {
          if (error) throw Error(" Failed to register and enroll " + userName + ": " + error);
          console.log("Enrolled %s successfully\n", userName);
          deploy(user); //사용자 정보를 deploy
      });      
   });
}

//@@ client 등록 후(enroll)
//@@ 모든 함수는 user.으로 실행 user.deploy(request문), user.invoke(request문)... 
// Deploy chaincode
//@@ 체인코드 배포
function deploy(user) {
   console.log("deploying chaincode; please wait ...");
   // Construct the deploy request
   // 배포 요청을 생성 : 체인코드명, 호출함수, 입력인자들
   var deployRequest = {
       chaincodeName: process.env.CORE_CHAINCODE_ID_NAME,
       fcn: "init",
       args: ["a", "100", "b", "200"]
   };
   // where is the chain code, ignored in dev mode
   //@@ 배포 대상이되는 체인코드의 경로를 셋
   deployRequest.chaincodePath = "github.com/hyperledger/fabric/examples/chaincode/go/chaincode_example02";

   // Issue the deploy request and listen for events
   //@@ 배포 요청을 하고, 이벤트를 수신
   var tx = user.deploy(deployRequest);
   tx.on('complete', function(results) {
       // Deploy request completed successfully
	   //@@ 배포 요청이 성공적으로 완료 되었을 경우,  
       console.log("deploy complete; results: %j",results);
       // Set the testChaincodeID for subsequent tests
	   //@@ 체인코드ID를 받음
       chaincodeID = results.chaincodeID;
       invoke(user); //@@ 배포는 특수한 invoke타입. 
   });
   tx.on('error', function(error) { //에러 발생시, 종료.
       console.log("Failed to deploy chaincode: request=%j, error=%k",deployRequest,error);
       process.exit(1);
   });

}

// Query chaincode
//@@ 체인코드 쿼리 
function query(user) {
   console.log("querying chaincode ...");
   // Construct a query request
   //@@ 쿼리 요청문을 생성 : 체인코드ID, 호출함수query, 함수 아규먼트
   var queryRequest = {
      chaincodeID: chaincodeID,
      fcn: "query",
      args: ["a"]
   };
   // Issue the query request and listen for events
   //@@ 쿼리 요청을 발행 하고 이벤트를 리슨.
   var tx = user.query(queryRequest);
   tx.on('complete', function (results) {
      console.log("query completed successfully; results=%j",results);
      process.exit(0);
   });
   tx.on('error', function (error) {
      console.log("Failed to query chaincode: request=%j, error=%k",queryRequest,error);
      process.exit(1);
   });
}

//Invoke chaincode
//@@ 체인코드 실행
function invoke(user) {
   console.log("invoke chaincode ...");
   // Construct a query request
   //체인코드 실행 요청문 작성 : 체인코드id, invoke함수호출, 함수 아규먼트
   var invokeRequest = {
      chaincodeID: chaincodeID,
      fcn: "invoke",
      args: ["a", "b", "1"]
   };
   // Issue the invoke request and listen for events
   //실행 요청을 발행하고, 이벤트를 리슨. 
   var tx = user.invoke(invokeRequest);
   tx.on('submitted', function (results) {
	      console.log("invoke submitted successfully; results=%j",results);	      
	   });   
   tx.on('complete', function (results) {
      console.log("invoke completed successfully; results=%j",results);
      query(user);      
   });
   tx.on('error', function (error) {
      console.log("Failed to invoke chaincode: request=%j, error=%k",invokeRequest,error);
      process.exit(1);
   });
}
