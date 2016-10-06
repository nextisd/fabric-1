/*
Copyright IBM Corp. 2016 All Rights Reserved.

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

package ledger

import (
	"fmt"
	"sync"

	"github.com/hyperledger/fabric/core/db"
	"github.com/hyperledger/fabric/protos"
	"github.com/tecbot/gorocksdb"
)

// blockchain_indexes.go       : blockchain indexer sync 구현
// blockchain_indexes_async.go : blockchain indexer async 구현

var lastIndexedBlockKey = []byte{byte(0)}

type blockWrapper struct {
	block       *protos.Block
	blockNumber uint64
	blockHash   []byte
	stopNow     bool
}

type blockchainIndexerAsync struct {
	blockchain *blockchain
	// Channel for transferring block from block chain for indexing
	//
	// 인덱싱 처리를 위한 블록 전송용 채널
	blockChan    chan blockWrapper
	indexerState *blockchainIndexerState
}

func newBlockchainIndexerAsync() *blockchainIndexerAsync {
	return new(blockchainIndexerAsync)
}

// blockchain async indexer 구현

func (indexer *blockchainIndexerAsync) isSynchronous() bool {
	return false
}

// start() : 인덱스 생성 시작
// start() -> indexPendingBlocks() -> fetchBlockFromDBAndCreateIndexes()
func (indexer *blockchainIndexerAsync) start(blockchain *blockchain) error {
	indexer.blockchain = blockchain
	// indexerState 설정 : RWMutex 락 처리, lastIndexedBlock 세팅
	indexerState, err := newBlockchainIndexerState(indexer)
	if err != nil {
		return err
	}
	indexer.indexerState = indexerState
	indexLogger.Debugf("staring indexer, lastIndexedBlockNum = [%d]",
		indexer.indexerState.getLastIndexedBlockNumber())

	// 대기중(pending)인 블록들을 일괄 인덱싱 처리.
	err = indexer.indexPendingBlocks()
	if err != nil {
		return err
	}
	indexLogger.Debugf("staring indexer, lastIndexedBlockNum = [%d] after processing pending blocks",
		indexer.indexerState.getLastIndexedBlockNumber())

	// 채널로 들어오는 블록들의 attribute에 대한 인덱스를 추가?
	indexer.blockChan = make(chan blockWrapper)
	go func() {
		for {
			indexLogger.Debug("Going to wait on channel for next block to index")
			blockWrapper := <-indexer.blockChan

			indexLogger.Debugf("Blockwrapper received on channel: block number = [%d]", blockWrapper.blockNumber)

			if blockWrapper.stopNow {
				indexLogger.Debug("stop command received on channel")
				indexer.blockChan <- blockWrapper
				return
			}
			if indexer.indexerState.hasError() {
				indexLogger.Debugf("Not indexing block number [%d]. Because of previous error: %s.",
					blockWrapper.blockNumber, indexer.indexerState.getError())
				continue
			}
			// createIndexesInternal() : 다양한 attribute에 대한 인덱스를 DB 항목에 추가함.
			err := indexer.createIndexesInternal(blockWrapper.block, blockWrapper.blockNumber, blockWrapper.blockHash)
			if err != nil {
				indexer.indexerState.setError(err)
				indexLogger.Debugf(
					"Error occured while indexing block number [%d]. Error: %s. Further blocks will not be indexed",
					blockWrapper.blockNumber, err)

			} else {
				indexLogger.Debugf("Finished indexing block number [%d]", blockWrapper.blockNumber)
			}
		}
	}()
	return nil
}

func (indexer *blockchainIndexerAsync) createIndexes(block *protos.Block, blockNumber uint64, blockHash []byte, writeBatch *gorocksdb.WriteBatch) error {
	indexer.blockChan <- blockWrapper{block, blockNumber, blockHash, false}
	return nil
}

// createIndexes adds entries into db for creating indexes on various attributes
//
// createIndexesInternal() : 다양한 attribute에 대한 인덱스를 DB 항목에 추가함.
func (indexer *blockchainIndexerAsync) createIndexesInternal(block *protos.Block, blockNumber uint64, blockHash []byte) error {
	openchainDB := db.GetDBHandle()
	writeBatch := gorocksdb.NewWriteBatch()
	defer writeBatch.Destroy()
	addIndexDataForPersistence(block, blockNumber, blockHash, writeBatch)
	writeBatch.PutCF(openchainDB.IndexesCF, lastIndexedBlockKey, encodeBlockNumber(blockNumber))
	opt := gorocksdb.NewDefaultWriteOptions()
	defer opt.Destroy()
	err := openchainDB.DB.Write(opt, writeBatch)
	if err != nil {
		return err
	}
	indexer.indexerState.blockIndexed(blockNumber)
	return nil
}

// fetchBlockNumberByBlockHash() : 블록해쉬값에 해당하는 블록번호 리턴.
func (indexer *blockchainIndexerAsync) fetchBlockNumberByBlockHash(blockHash []byte) (uint64, error) {
	err := indexer.indexerState.checkError()
	if err != nil {
		indexLogger.Debug("Async indexer has a previous error. Returing the error")
		return 0, err
	}
	indexer.indexerState.waitForLastCommittedBlock()
	return fetchBlockNumberByBlockHashFromDB(blockHash)
}

// fetchTransactionIndexByID() : txID에 해당하는 트랜잭션 인덱스 리턴.
func (indexer *blockchainIndexerAsync) fetchTransactionIndexByID(txID string) (uint64, uint64, error) {
	err := indexer.indexerState.checkError()
	if err != nil {
		return 0, 0, err
	}
	indexer.indexerState.waitForLastCommittedBlock()
	return fetchTransactionIndexByIDFromDB(txID)
}

// indexPendingBlocks() : 대기중(pending)인 블록들을 인덱싱 처리.
func (indexer *blockchainIndexerAsync) indexPendingBlocks() error {
	blockchain := indexer.blockchain
	if blockchain.getSize() == 0 {
		// chain is empty as yet
		return nil
	}

	lastCommittedBlockNum := blockchain.getSize() - 1
	lastIndexedBlockNum := indexer.indexerState.getLastIndexedBlockNumber()
	zerothBlockIndexed := indexer.indexerState.isZerothBlockIndexed()

	indexLogger.Debugf("lastCommittedBlockNum=[%d], lastIndexedBlockNum=[%d], zerothBlockIndexed=[%t]",
		lastCommittedBlockNum, lastIndexedBlockNum, zerothBlockIndexed)

	// block numbers use uint64 - so, 'lastIndexedBlockNum = 0' is ambiguous.
	// So, explicitly checking whether zero-th block has been indexed
	//
	// block number는 uint64를 사용함. 그래서, 'lastIndexedBlockNum = 0'는 모호한 표현임.
	// 따라서, 0번째 블록이 인덱싱 되었는지를 명시적으로 체크함.
	if !zerothBlockIndexed {
		err := indexer.fetchBlockFromDBAndCreateIndexes(0)
		if err != nil {
			return err
		}
	}

	if lastCommittedBlockNum == lastIndexedBlockNum {
		// all committed blocks are indexed
		//
		// 모든 커밋된 블록들이 인덱싱 되었음.
		return nil
	}

	for ; lastIndexedBlockNum < lastCommittedBlockNum; lastIndexedBlockNum++ {
		blockNumToIndex := lastIndexedBlockNum + 1
		err := indexer.fetchBlockFromDBAndCreateIndexes(blockNumToIndex)
		if err != nil {
			return err
		}
	}
	return nil
}

// fetchBlockFromDBAndCreateIndexes() : 입력 블록높이에 해당하는 블록을 DB에서 가져온 뒤, 인덱스 생성.
func (indexer *blockchainIndexerAsync) fetchBlockFromDBAndCreateIndexes(blockNumber uint64) error {
	blockchain := indexer.blockchain
	blockToIndex, errBlockFetch := blockchain.getBlock(blockNumber)
	if errBlockFetch != nil {
		return errBlockFetch
	}

	blockHash, errBlockHash := blockToIndex.GetHash()
	if errBlockHash != nil {
		return errBlockHash
	}
	indexer.createIndexesInternal(blockToIndex, blockNumber, blockHash)
	return nil
}

func (indexer *blockchainIndexerAsync) stop() {
	indexer.indexerState.waitForLastCommittedBlock()
	indexer.blockChan <- blockWrapper{nil, 0, nil, true}
	<-indexer.blockChan
	close(indexer.blockChan)
}

// Code related to tracking the block number that has been indexed
// and if there has been an error in indexing a block
// Since, we index blocks asynchronously, there may be a case when
// a client query arrives before a block has been indexed.
//
// Do we really need strict semantics such that an index query results
// should include up to block number (or higher) that may have been committed
// when user query arrives?
// If a delay of a couple of blocks are allowed, we can get rid of this synchronization stuff
//
// 아래 코드는 인덱싱된 블록 번호, 블록 인덱싱중 에러 발생을 추적하는것에 대한 내용임.
// 비동기적으로 블록 인덱싱시에는 블록 인덱스가 생성되기 이전에 클라이언트 쿼리가 도착하는 경우가 발생할 수 있다.
//
// 만약 2개 블록이 딜레이 되는것을 허용했을 경우, 우리는 이 동기화 부분을 삭제해도 됨.
type blockchainIndexerState struct {
	indexer *blockchainIndexerAsync

	zerothBlockIndexed bool
	lastBlockIndexed   uint64
	err                error
	lock               *sync.RWMutex
	newBlockIndexed    *sync.Cond
}

// newBlockchainIndexerState(): RWMutex 락 처리, lastIndexedBlock 세팅
// indexer.start()에서 호출
func newBlockchainIndexerState(indexer *blockchainIndexerAsync) (*blockchainIndexerState, error) {
	var lock sync.RWMutex
	zerothBlockIndexed, lastIndexedBlockNum, err := fetchLastIndexedBlockNumFromDB()
	if err != nil {
		return nil, err
	}
	return &blockchainIndexerState{indexer, zerothBlockIndexed, lastIndexedBlockNum, nil, &lock, sync.NewCond(&lock)}, nil
}

// blockIndexed() : indexerState구조체에 lastBlockIndex, zerothBlockIndexed 세팅.
// 대기중인 모든 고루틴(indexerState.newBlockindexed.*)에 새로운 블록이 인덱스 되었다고 broadcast 처리.
func (indexerState *blockchainIndexerState) blockIndexed(blockNumber uint64) {
	indexerState.newBlockIndexed.L.Lock()
	defer indexerState.newBlockIndexed.L.Unlock()
	indexerState.lastBlockIndexed = blockNumber
	indexerState.zerothBlockIndexed = true
	indexerState.newBlockIndexed.Broadcast()
}

// getLastIndexedBlockNumber() : 마지막 인덱싱된 블록 번호 리턴.
func (indexerState *blockchainIndexerState) getLastIndexedBlockNumber() uint64 {
	indexerState.lock.RLock()
	defer indexerState.lock.RUnlock()
	return indexerState.lastBlockIndexed
}

// isZerothBlockIndexed() : 0번째 블록 인덱싱 되었는지 리턴.
func (indexerState *blockchainIndexerState) isZerothBlockIndexed() bool {
	indexerState.lock.RLock()
	defer indexerState.lock.RUnlock()
	return indexerState.zerothBlockIndexed
}

// waitForLastCommittedBlock() : 처리중인 인덱싱이 종료될때까지 락 걸고 대기.
func (indexerState *blockchainIndexerState) waitForLastCommittedBlock() error {
	indexLogger.Debugf("waitForLastCommittedBlock() indexerState.err = %#v", indexerState.err)
	chain := indexerState.indexer.blockchain
	indexerState.lock.Lock()
	defer indexerState.lock.Unlock()
	if indexerState.err != nil {
		return indexerState.err
	}

	if chain.getSize() == 0 {
		return nil
	}

	lastBlockCommitted := chain.getSize() - 1

	if !indexerState.zerothBlockIndexed {
		indexLogger.Debugf(
			"Waiting for zeroth block to be indexed. lastBlockCommitted=[%d] and lastBlockIndexed=[%d]",
			lastBlockCommitted, indexerState.lastBlockIndexed)
		indexerState.newBlockIndexed.Wait()
	}

	for indexerState.lastBlockIndexed < lastBlockCommitted && indexerState.err == nil {
		indexLogger.Debugf(
			"Waiting for index to catch up with block chain. lastBlockCommitted=[%d] and lastBlockIndexed=[%d]",
			lastBlockCommitted, indexerState.lastBlockIndexed)
		indexerState.newBlockIndexed.Wait()
	}
	return indexerState.err
}

func (indexerState *blockchainIndexerState) setError(err error) {
	indexerState.lock.Lock()
	defer indexerState.lock.Unlock()
	indexerState.err = err
	indexLogger.Debugf("setError() indexerState.err = %#v", indexerState.err)
	indexerState.newBlockIndexed.Broadcast()
}

func (indexerState *blockchainIndexerState) hasError() bool {
	indexerState.lock.RLock()
	defer indexerState.lock.RUnlock()
	return indexerState.err != nil
}

func (indexerState *blockchainIndexerState) getError() error {
	indexerState.lock.RLock()
	defer indexerState.lock.RUnlock()
	return indexerState.err
}

func (indexerState *blockchainIndexerState) checkError() error {
	indexerState.lock.RLock()
	defer indexerState.lock.RUnlock()
	if indexerState.err != nil {
		return fmt.Errorf(
			"An error had occured during indexing block number [%d]. So, index is out of sync. Detail of the error = %s",
			indexerState.getLastIndexedBlockNumber()+1, indexerState.err)
	}
	return indexerState.err
}

// fetchLastIndexedBlockNumFromDB() :zerothBlockIndexed 여부와 최종블록번호 리턴.
func fetchLastIndexedBlockNumFromDB() (zerothBlockIndexed bool, lastIndexedBlockNum uint64, err error) {
	lastIndexedBlockNumberBytes, err := db.GetDBHandle().GetFromIndexesCF(lastIndexedBlockKey)
	if err != nil {
		return
	}
	if lastIndexedBlockNumberBytes == nil {
		return
	}
	lastIndexedBlockNum = decodeBlockNumber(lastIndexedBlockNumberBytes)
	zerothBlockIndexed = true
	return
}
