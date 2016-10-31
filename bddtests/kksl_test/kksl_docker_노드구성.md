#### 4VP, 1CA 구성 : docker-compose 파일

- - -

- **ver0.6 기준**
	core.yaml, membersrvc.yaml
    (mode: dev->net, 기타 security : true)

	1. docker-compose-4-consensus-batch.yml 파일을 docker-compose.yml 파일로 복사
	2. docker-compose-4-consensus-base.yml 파일은 수정사항 없음
	3. compose-defaults.yml 파일 수정
	`- CORE_VM_END_POINT=unix:///var/run/docker.sock으로 수정`
    `volumes:    - var/run/docker.sock/:/var/run/docker.sock 추가`
    4. 1~3 해봐도 처리 안될경우( latest image를 못 찾아올 경우)
        1. docker pull hyperledger/fabric-baseimage:x86_64-0.1.0
        2. docker tag hyperledger/fabric-baseimage:x86_64-0.1.0 hyperledger/fabric-baseimage:latest
