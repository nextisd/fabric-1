##kksl_AttributesUsage.md

- Chaincode는 transaction certificate의 확장 데이터를 attribute 기능을 통해 사용할 수 있음


- Attribute는 ACA(Attributes Certificate Authority)를 통해 인증됨


- Use case : Authorizable counter
     - ABAC(Attributed Based Access Control)을 통해 transaction certificate에 attribute에 접근
     - ABAC API(stub.VerifiyAttribute())를 통해 검증이 되면 카운터 증가
     - peer chaincode deploy/invoke '-a' 플래그로 사용자 Attribute를 지정할 수 있음(JSON 포맷)