##ledger.go



	type Ledger struct {
		blockchain *blockchain
		state      *state.State
		currentID  interface{}
	}
- **GetLedger()**
	- 'singleton' ledger 객체 레퍼런스 리턴
- **GetNewLedger()**
---
#### Transaction-batch related methods #####

- **BeginTxBatch()**
	+ 트랜잭션 일괄처리(transaction-batch) 다음 라운드가 시작될때 호출됨(invoked)


- **GetTXBatchPreviewBlockInfo()**
	+ ledger.CommitTxBatch()가 실행된 이후 GetBlockchainInfo() 리턴값과 동일한 '이전 블록 정보'를 리턴.
    + 두개의 call 사이에 state 변경이 있을 경우는 리턴될 hash값들은 다를 수 있음


- **CommitTxBatch()**
	+ transaction-batch가 commit될 필요가 있을때 호출됨.
	+ 트랜잭션 처리, state change가 정상적으로 스토리지에 commit 되었을때 정상 리턴됨.


- **RollbackTxBatch()**
    + transaction-batch 실행중 일어났을수 있는 모든 상태 변경분을 롤백.


- **TxBegin()**
    - 진행중인 batch의 새로운 트랜잭션의 시작 마킹, state.currentID = txID 처리.
    - 트랜잭션이 이미 실행중일때 호출할 경우 panic 발생


- **TxFinished()**
    - 진행중인 트랜잭션의 종료 마킹.
`   state.currentTxStateDelta = statemgmt.NewStateDelta()
    state.currentTxID = ""`

---
#### World-state related methods #####

- **GetTempStateHash()**
    + account에 현재 transaction-batch를 처리하는 동안 상태 변화를 포함한 state hash값을 계산.

- **GetTempStateHashWithTxDeltaStateHashes()**
	+ GetTempStateHash()에서 정의된 state hash값에 상태변경 map(txUuid of Tx)의 해쉬값을 추가로 리턴함
`state.stateDelta.ApplyChanges(state.currentTxStateDelta)`
`state.txStateDeltaHash[txID] =state.currentTxStateDelta.ComputeCryptoHash()`


- **GetState() **
    + ChaincodeID/key로 state 조회.
        * @param committed(false) : memory -> db 순서로 검색.
        * @param committed(true)  : db 에서만 가져옴.


- **GetStateRangeScanIterator()**
    + chaincodeID에 해당하는 startKey~endKey 사이의 모든 Key-Value를 사전순으로 리턴함(iterator)
		* @param committed(true) : key-value는 DB에서만 가져옴
		* @param committed(false): DB로부터 가져온 결과를 memory에서 가져온 결과와 통합(in-memory데이터에 우선권을 줌)
	+ 리턴된 interator의 key-value는 특정한 순서를 보장하지는 않음.



- **DeleteState()**
	+ chaincodeID와 key에 해당하는 value(state)의 삭제처리. DB에 바로 쓰지는 않음


- **GetStateMultipleKeys()**
	+ 여러개의 key에 대한 value를 리턴.
	+ chaincode와 shim peer간의 grpc 처리 부하를 줄일 수 있음.


- **SetStateMultipleKeys()**
    + 여러개의 key에 대한 value를 설정.
    + chaincode와 shim peer간의 grpc 처리 부하를 줄일 수 있음.


- **GetStateSnapshot()**
    + 현재 블록의 global state에 대한 스냅샷을 리턴.
	+ 피어에서 다른 피어로 state를 전송할때 사용해야함.
	+ 실행완료 후 스냅샷에 대한 자원 반환을 위해 stateSnapshot.Release()를 꼭 호출해야함!


- **GetStateDelta()**
    + 특정한 블록의 state delta를 리턴.
	+ 처리가 불가한 경우는 nil,nil이 리턴됨.


- **ApplyStateDelta()**
    + 현재의 state에 state delta를 적용함.
    + in-memory에만 변경이 되며, 영구적인 반영을 위해서는 ledger.CommitStateDelta를 호출해야함.
    + 상태 동기화(state synchronization) 처리시에만 사용되어야 하는 함수임.

    >State delta : e.g. ledger_test.go의 TestSetRawState() 참고
    >> 1.다른 피어에서 Ledger.GetStateDelta를 실행한 결과를 통해서 얻을 수 있고
    >>2.Ledger.GetStateSnapshot()에서 리턴된 key를 기반으로 state delta를 생성
    + 이 함수에서는 order check가 없으며 호출자가 delta들이 적절한 순서로 적용되었는지를 확인해야 함.
    + 예를들면, 만약 당신이 현재 block8 에 있을때, Ledger.GetStateDelta(10)에서 리턴된 delta를 인자로 사용해서 이 함수를 호출하였을 경우, 당신은 block9에 대한 delta를 apply 하지 않았기 때문에 bad state가 된다.
    + stateDelta.RollBackward를 통해 state를 roll foward/backward 하는게 가능함.
	+ 기본적으로, block3에서 가져온 delta는 block2에서 block3로 roll forwards할때 사용할 수 있다.
	+ 만약, stateDelta.RollBackwards=false라면 block3에서 가져온 delta는 block3에서 block2로 roll backwards시 사용 할수 있다.


- **CommitStateDelta()**
    + state delta를 ledger.ApplyStateDelta에서 DB로 commit 처리

- **RollbackStateDelta()**
    + state delta 롤백

- **DeleteALLStateKeysAndValues()**
    + state의 모든 key-value를 삭제.
    + snapshot으로 부터 new state를 생성할때 state synchronization을 할때만 사용하는게 일반적임

---
#### Transaction-batch related methods #####

- **GetBlockchainInfo()**
    + blockchain ledger 정보 조회(height, current/previous block hash,...)


- **GetBlockByNumber()**
    + 블록 번호(높이)에 해당하는 블록 리턴


- **GetBlockchainSize()**
    + 총 블록개수 리턴



- **GetTransactionByID()**
    + txID에 해당하는 트랜잭션 리턴



- **PutRawBlock()**
    + raw block을 블록체인에 추가. 피어간 동기화시에만 사용해야함!


- **VerifyChain()**
    + blockchain의 무결성 검증시 사용.
    + 블록내부의 이전블록해쉬값이 실제 블록체인상의 이전 블록의 해쉬값과 동일한지를 검증함
    + VerifyChain(0,99)와 같이 범위를 지정할수 있고 만약, 8, 32, 42 블록에서 이전블록해쉬값이 불일치 할경우, 42블록을 에러로 리턴함.
>@param highBlock : 시작블록, 모든 블록을 검증하려ledger.GetBlockchainSize()-1 을 세팅.
 @param lowBlock  : 종료블록, 모든 블록을 검증하려면 0을 세팅(genesis block)
 
 

- **checkValidIDBegin()**

- **checkValidIDCommitORRollback()**

- **resetForNextTxGroup()**

- **sendProducerBlockEvent()**

- **sendChaincodeEvents()**

