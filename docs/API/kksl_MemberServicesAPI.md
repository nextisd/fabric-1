##kksl_MemberServicesAPI.md

- 인증기관(CA) API : 각각의 CA 서비스는 두개의 GRPC 인터페이스 제공
     - public (접미사 '~P') and administrator (접미사 '~A')

	1. Enrollment Certificate Authority(ECA, 등록인증기관)
     	- ECAA : 신규 유저 등록(ECAP에서 사용할 user ID/OTP 리턴) 및 유저 리스트 조회 제공
     	- ECAP : ECA 자신의 인증서 조회, 인증서Pair를 신규 생성후 유저에게 제공(OTP인증 후 challenge인증)

	2. Transaction Certificate Authority(TCA, 거래인증기관)
     	- TCAA : 미구현
	  	- TCAP : TCA 자신의 인증서 조회, 유저에게 신규 트랜잭션 인증서 발급

	3. TLS Certificate Authority
     	- TLSCAA : 미구현
     	- TLSCAP : TLSCA 자신의 인증서 조회, 유저에게 신규 TLS 인증서 발급


