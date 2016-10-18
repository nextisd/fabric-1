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

/**
 * This example shows how to do the following in a web app.
 * 1) At initialization time, enroll the web app with the blockchain.
 *    The identity must have already been registered.
 * 2) At run time, after a user has authenticated with the web app:
 *    a) register and enroll an identity for the user;
 *    b) use this identity to deploy, query, and invoke a chaincode.
 */
//@@ web에서 돌아가는 application을 구현하는 방법
//@@ 1) 초기 : 블록체인에 web app을 enroll (기등록(register)되어 있어야 함)
//@@ 2) 실행 시점 : web app admin으로 부터 허가된 사용자는 deploy, query, invoke 체인코드를 할 수 있다.
var hfc = require('hfc');

//get the addresses from the docker-compose environment
var PEER_ADDRESS         = process.env.PEER_ADDRESS;
var MEMBERSRVC_ADDRESS   = process.env.MEMBERSRVC_ADDRESS;

// Create a client chain.
// The name can be anything as it is only used internally.
var chain = hfc.newChain("targetChain");

// Configure the KeyValStore which is used to store sensitive keys
// as so it is important to secure this storage.
// The FileKeyValStore is a simple file-based KeyValStore, but you
// can easily implement your own to store whereever you want.
// To work correctly in a cluster, the file-based KeyValStore must
// either be on a shared file system shared by all members of the cluster
// or you must implement you own KeyValStore which all members of the
// cluster can share.
//@@ FileKeyValStore는 간단한 파일 베이스의 key value 스토어. 
//@@ 하지만, 사용자가 편의대로 store구성을 바꿀 수 있다. 작업 디렉토리는 클러스터에 있으며,
//@@ key value store는 클러스터 내의 모든 멤버들에게 공유된 파일 시스템에 있어야 한다.
//@@ (사용자가 따로 구성한 store도 역시 클러스터 내 모든 멤버들에게 공유가 가능해야 한다.)
chain.setKeyValStore( hfc.newFileKeyValStore('/tmp/keyValStore') );

// Set the URL for membership services
chain.setMemberServicesUrl("grpc://MEMBERSRVC_ADDRESS");

// Add at least one peer's URL.  If you add multiple peers, it will failover
// to the 2nd if the 1st fails, to the 3rd if both the 1st and 2nd fails, etc.
//@@적어도 하나 이상의 peer와 연결이 되어야 한다.
//@@여러 피어가 붙을 경우에는, 그 중 하나의 피어와 연결에 문제가 있을 경우, 다른 피어들로 failover된다. 
chain.addPeer("grpc://PEER_ADDRESS");

// Enroll "WebAppAdmin" which is already registered because it is
// listed in fabric/membersrvc/membersrvc.yaml with its one time password.
// If "WebAppAdmin" has already been registered, this will still succeed
// because it stores the state in the KeyValStore
// (i.e. in '/tmp/keyValStore' in this sample).
//@@ WebAppAdmin은 membersrvc.yaml에 정의되어 기등록되어 있다. 
chain.enroll("WebAppAdmin", "DJY27pEnl16d", function(err, webAppAdmin) {
   if (err) return console.log("ERROR: failed to register %s: %s",err);
   // Successfully enrolled WebAppAdmin during initialization.
   // Set this user as the chain's registrar which is authorized to register other users.
   chain.setRegistrar(webAppAdmin);
   // Now begin listening for web app requests
   // web app상의 요청 수신 대기
   listenForUserRequests();
});

// Main web app function to listen for and handle requests.  This is specific to
// your application but is provided here to demonstrate the pattern.
// 주요 web app 펑션으로, 요청을 수신 대기하고 핸들링한다. (실제 사용자가 구현할 부분)
function listenForUserRequests() {
   for (;;) {
      // WebApp-specific logic goes here to await the next request.
      // ...
      // Assume that we received a request from an authenticated user 
	  // and have 'userName' and 'userAccount'.
	  // Then determined that we need to invoke the chaincode
      // with 'chaincodeID' and function named 'fcn' with arguments 'args'.
      handleUserRequest(userName,userAccount,chaincodeID,fcn,args);
   }
}

// Handle a user request
// 위에서 수신한 요청을 실제 핸들링 하는 부분
function handleUserRequest(userName, userAccount, chaincodeID, fcn, args) {
   // Register and enroll this user.
   // If this user has already been registered and/or enrolled, this will
   // still succeed because the state is kept in the KeyValStore
   // (i.e. in '/tmp/keyValStore' in this sample).
   // 사용자를 등록하고, 
   var registrationRequest = {
	         roles: [ 'client' ],
	         enrollmentID: userName,
	         affiliation: "bank_a",
	         attributes: [{name:'role',value:'client'},{name:'account',value:userAccount}]
	    };
   chain.registerAndEnroll( registrationRequest, function(err, user) {
      if (err) return console.log("ERROR: %s",err);
      // Issue an invoke request
      var invokeRequest = {
        // Name (hash) required for invoke
        chaincodeID: chaincodeID,
        // Function to trigger
        fcn: fcn,
        // Parameters for the invoke function
        args: args
     };
     // Invoke the request from the user object and wait for events to occur.
	 // 사용자 객체의 invoke를 실행하고 이벤트를 수신 대기
     var tx = user.invoke(invokeRequest);
     // Listen for the 'submitted' event
	 // 요청이 제대로 제출되었다는 submitted 메세지를 수신시 정상 처리 
     tx.on('submitted', function(results) {
        console.log("submitted invoke: %j",results);
     });
     // Listen for the 'complete' event.
	 // 제출한 요청이 정상적으로 실행 완료 되었다는 이벤트 메세지 수신시 정상 처리.
     tx.on('complete', function(results) {
        console.log("completed invoke: %j",results);
     });
     // Listen for the 'error' event.
	 // 에러 발생시
     tx.on('error', function(err) {
        console.log("error on invoke: %j",err);
     });
   });
}