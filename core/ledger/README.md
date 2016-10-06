## Ledger Package

This package implements the ledger, which includes the blockchain and global state.

If you're looking for API to work with the blockchain or state, look in `ledger.go`. This is the file where all public functions are exposed and is extensively documented. The sections in the file are:

### Transaction-batch functions

These are functions that consensus should call. `BeginTxBatch` followed by `CommitTxBatch` or `RollbackTxBatch`. These functions will add a block to the blockchain with the specified transactions.

### World-state functions

These functions are used to modify the global state. They would generally be called by the VM based on requests from chaincode.

### Blockchain functions

These functions can be used to retrieve blocks/transactions from the blockchain or other information such as the blockchain size. Addition of blocks to the blockchain is done though the transaction-batch related functions.

---
# (KKSL) Ledger Package
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
