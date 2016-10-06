##kksl_index.md

[Hyperledger Fabric Index Page]


#### - Incubation Notice
  - 하이퍼렛저 프로젝트 인큐베이션 공지사항 (e.g. IBM+DAH Codebase 합병 등)

**- Hyperledger Fabric**
  - Releases : v0.5-developer-preview
  - Contribute 방법 : source clone - update - Gerrit review
  - Project Maintainer List : TSC Guideline에 따라 프로젝트 관리
  - Communication : Hyperledger Slack, Google Hangout 사용
  - Q&A : StackOverflow 이용


**- Getting started**
  - Whiterpaper WG : 하이퍼렛저 백서 발간 (최신 Draft v2.0.0, 2016.8.3)
  - Requirement WG : 프로젝트 요구사항 및 Usecase 
  - Canonical use cases : Usecase 모음
  - Glossary : 용어 정의
  - Fabric FAQs

**- Quickstart**
  - Development environment set-up : 개발환경 세팅
     - Host->VM(vagrant)-> Docker
     - Git,Go,Vagrant,VirtualBox 설치 및 BIOS설정
     - GOPATH 환경변수 설정
     - Fabric 프로젝트 git clone
     - Vagrant 실행 및 Fabric peer 빌드 및 테스트


  - Network setup
     - 로컬 환경에서 Docker 기반으로 네트워크 설정 후 피어간 통신 및 컨센서스 설정


  - Chaincode development environment
     - peer network를 구성하지 않고도 체인코드 개발 및 테스트를 진행할 수 있음( --peer-chincodedev flag 이용)
     - Java chaincode setup 문서 별도 존재
     - 3가지 개발 방식 : Vagrant, Docker for windows, Docker toolbox
     - Vagrant/Docker 이용 peer 및 CA를 실행시킨 뒤 Chaincode 실행
     - CLI 또는 REST API 이용 chaincode를 deploy/invoke/query



  - APIs
     - 3가지 방식으로 peer node와 유저간 통신
       1. CLI : peer node/network/chaincode/help 등 커맨드라인 실행
       2. REST API : Endpoints(Block/Blockchain/Chaincode/Network/Registar/Transactions)                            Swagger-UI 셋업 : REST API 문서화 툴
       3. Node.js Application :
           - REST API 구축시 생성된 rest_api.json + swagger-js plugin 사용 또는
           - IBM Blockchain JS SDK 사용해서 구축



* Developer guides (protocol spec. 먼저 읽기)
  Fabric developer's guide
  - Code Contributions 가이드라인
  - 개발 환경 세팅(위에서 설명, Quickstart)
  - Building the fabric core : vagrant 또는 docker(vagrant 밖에서 빌드), 유닛 테스트 실행
  - Logging Control : github.com/op/go-logging 패키지를 사용하여 로깅
     @ peer application과 shim interface(chaincode)에서 사용
     @ peer간 통신시 로그레벨 지정
     @ chaincode 실행시 사용자 정의 로그 정의
  - License Header : 모든 소스코드상에 포함되어야할 저작권 문구


 ** Chaincode developer's guide
  - Setting up the development environment : 개발 환경 세팅(상동, Qukckstart)
  - Setting up a network for development : 
     @ 로컬 환경에서 Docker 기반으로 네트워크 설정 후 피어간 통신 및 컨센서스 설정
  - 체인코드 작성,빌드,실행 환경 구축 방법(상동, Quickstart)

 ** API developer's guide
  - 위에서 설명, Quickstart APIs 참고

* Operations guide
  - Setting Up a network : fabric peer 간 네트워크 설정
  - Certificate Authority (CA) Setup : 인증기관(CA) 서비스 설정
     @ 사용자등록(User enrollment), 트랜잭션 실행(invoked transaction), TLS-secured connections간 인증에 사용함
     @ 1.Enrollment Certificate Autority(ECA, 등록 인증 기관)
        ;새로운 사용자를 블록체인에 등록하고 인증키(공개키/개인키) 생성
     @ 2.Transaction Certificate Authority(TCA, 거래 인증 기관)
        ;등록된 사용자는 TCA로 부터 트랜잭션 인증서를 받아서 Chaincode를 Deploy/Invoke 할 수 있음
        ;하나의 인증서로 여러개의 트랜잭션이 처리 가능하나, 보안을 위해 1트랜잭션-1인증서를 권장함 
     @ 3.TLS Certificate Authority(TLSCA, TCS 인증 기관)
        ;EC,TC 인증외에도 커뮤니케이션 채널 보안을 위한 TLS 인증 처리
     @ 모든 CA는 단일 프로세스로 실행되며 membersrvc.yaml을 설정파일로 사용
     @ 소스코드로 부터 build and run 하거나 Docker Compose로 기생성된 이미지를 사용하여 기동할 수 있음

  - Application ACL : 애플리케이션 액세스 제어 목록(Access Control Lists)
     @ 1. ~ HelloWorld : hello() 함수 호출하는 체인코드
     @ 2. ~ Alice : HelloWorld Deployer
     @ 3. ~ Bob : HelloWorld's function invoker
     @ 4. ~ Alice는 Bob만 hello()를 실행할 권한을 주려고 함
     @ [Fabric Support]
        ; Alice가 자신의 ACL에 Bob을 추가할수 있도록 fabric에서 접근 제어 기능 제공함(아래 interface)
        ; 1. Certificate Handler - TCert/ECert 인증서를 통해 메시지에 사인/검증
        ; 2. Transaction Handler - 트랜잭션 생성후 접근 제어 및 data와 tx간 binding제공
        ; 3. Client Handler - 위의 interface들의 instance에 접근 제공
        ; 4. Transaction Format - 애플리케이션 레벨의 ACL 구현을 위해서는 tx에 metadata 항목을 추가해야함
        ; 5. Validator - 체인코드 실행시, 위에서 추가된 metadata 및 binding정보를 제공해야 함
     @ [Application Level access control]
        ; 1. Deploy Transaction
        ;   a) Alice는 tx의 function마다 ACL을 설정하여 권한을 지정할 수 있음, TCert/ECert 이용, metadata에 저장
        ;   b) 체인코드의 함수의 인자 또는 함수명을 이용하여 hello()를 호출하기 위한 message M을 정의함
        ; 2. Execute Transaction
        ;   a) Bob이 hello()를 invoke하기 위해 message M에 TCert/ECert로 sign이 필요함
        ;   b) Bob은 해당 인증서를 획득, 트랜잭션 핸들러 바인딩후 M과 함께 sign함
        ;   c) Bob은 새로운 트랜잭션을 실행(invoke), signature는 트랜잭션의 metadata에 포함되서 전송됨
        ; 3. Chaincode Execution
        ;   a) Bob이 실행한 트랜잭션을 수신받은 validator는 트랜잭션의 binding 및 metadata를 hello() 함수 실행시 제공함
        ;   b) hello() function은 포함된 signature의 유효성을 체크해야 한다(ACL상의 Bob이 맞는지)

  - License : 하이퍼렛저 프로젝트는 Apache 2.0 라이선스를 사용함
    (배포/수정 자유, No Copyleft, 저작권문구만 포함)


      


"
