# KKSL_Ledger Package
---

- Ledger 패키지는 blockchain과 global state를 저장하는 ledger를 구현함

	- ledger.go : blockchain 또는 state를 처리할 API 구현(all public functions)
		1. Transaction-batch functions
			- consensus에서 호출되어야할 함수들
			- *'BeginTxBatch'* -> *'CommitTxBatch'* or *'RollbackTxBatch'*
			- 위 함수들을 통해 tx들로 구성된 블록을 추가함

		2. World-state functions
			- global state 변경시 호출
			- chaincode request로 생성한 VM으로부터 호출됨

		3. Blockchain functions
			- blocks/transactions 검색
			- 기타 정보(e.g. blockchain size)
			- 블록체인에 블록추가등은 Transaction-batch functions에서 구현됨

