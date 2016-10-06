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
	"bytes"
	"encoding/binary"
	"strconv"

	"github.com/hyperledger/fabric/core/db"
	"github.com/hyperledger/fabric/core/util"
	"github.com/hyperledger/fabric/protos"
	"github.com/tecbot/gorocksdb"
	"golang.org/x/net/context"
)

// Blockchain holds basic information in memory. Operations on Blockchain are not thread-safe
// TODO synchronize access to in-memory variables
//
// blockchain 구조체는 기본적인 정보를 메모리에 저장.
// blockchain 구조체는 thread-safe 하지 않게 접근 가능함, 여러 객체에서 공유해서 사용가능, 락처리 없음
// TODO in-memory 변수에 대한 동기화 접근 구현 필요
type blockchain struct {
	size               uint64
	previousBlockHash  []byte
	indexer            blockchainIndexer
	lastProcessedBlock *lastProcessedBlock
}

type lastProcessedBlock struct {
	block       *protos.Block
	blockNumber uint64
	blockHash   []byte
}

var indexBlockDataSynchronously = true

// newBlockchain() : 신규 블록체인 생성, Ledger.GetNewLedger()에서 호출
	size, err := fetchBlockchainSizeFromDB()
	if err != nil {
		return nil, err
	}
	blockchain := &blockchain{0, nil, nil, nil}
	blockchain.size = size
	if size > 0 {
		previousBlock, err := fetchBlockFromDB(size - 1)
		if err != nil {
			return nil, err
		}
		previousBlockHash, err := previousBlock.GetHash()
		if err != nil {
			return nil, err
		}
		blockchain.previousBlockHash = previousBlockHash
	}

	err = blockchain.startIndexer()	// nil 리턴으로 박혀있음.
	if err != nil {
		return nil, err
	}
	return blockchain, nil
}

////////////////////////////////////////////////////////////////////
// blockchain 구조체 메서드 연결
////////////////////////////////////////////////////////////////////

// startIndexer() : blockchain indexer 생성
// interfaces :	isSynchronous()
// 				start()
//				createIndexes()
//				fetchBlockNumberByBlockHash()
//				fetchTransactionIndexByID()
func (blockchain *blockchain) startIndexer() (err error) {
	if indexBlockDataSynchronously {
		blockchain.indexer = newBlockchainIndexerSync()
	} else {
		blockchain.indexer = newBlockchainIndexerAsync()
	}
	err = blockchain.indexer.start(blockchain)
	return
}

// getLastBlock get last block in blockchain
//
// getLastBlock() : 블록체인 내 마지막 블록 리턴
func (blockchain *blockchain) getLastBlock() (*protos.Block, error) {
	if blockchain.size == 0 {
		return nil, nil
	}
	return blockchain.getBlock(blockchain.size - 1)
}

// getSize number of blocks in blockchain
//
// getSize() : 블록체인 내 블록의 개수 리턴
func (blockchain *blockchain) getSize() uint64 {
	return blockchain.size
}

// getBlock get block at arbitrary height in block chain
//
// getBlock() : @blockNumber에 해당하는 블록 리턴
func (blockchain *blockchain) getBlock(blockNumber uint64) (*protos.Block, error) {
	return fetchBlockFromDB(blockNumber)
}

// getBlockByHash get block by block hash
// 
// getBlockByHash() : @blockHash에 해당하는 블록 리턴
func (blockchain *blockchain) getBlockByHash(blockHash []byte) (*protos.Block, error) {
	blockNumber, err := blockchain.indexer.fetchBlockNumberByBlockHash(blockHash)
	if err != nil {
		return nil, err
	}
	return blockchain.getBlock(blockNumber)
}

// getTransactionByID() : @txID에 해당하는 트랜잭션 리턴
func (blockchain *blockchain) getTransactionByID(txID string) (*protos.Transaction, error) {
	blockNumber, txIndex, err := blockchain.indexer.fetchTransactionIndexByID(txID)
	if err != nil {
		return nil, err
	}
	block, err := blockchain.getBlock(blockNumber)
	if err != nil {
		return nil, err
	}
	transaction := block.GetTransactions()[txIndex]
	return transaction, nil
}

// getTransactions get all transactions in a block identified by block number
//
// getTransactions() : @blockNumber에 해당하는 블록의 모든 트랜잭션들을 리턴
func (blockchain *blockchain) getTransactions(blockNumber uint64) ([]*protos.Transaction, error) {
	block, err := blockchain.getBlock(blockNumber)
	if err != nil {
		return nil, err
	}
	return block.GetTransactions(), nil
}

// getTransactionsByBlockHash get all transactions in a block identified by block hash
//
// getTransactionsByBlockHash() : @blockHash에 해당하는 블록의 모든 트랜잭션들을 리턴
func (blockchain *blockchain) getTransactionsByBlockHash(blockHash []byte) ([]*protos.Transaction, error) {
	block, err := blockchain.getBlockByHash(blockHash)
	if err != nil {
		return nil, err
	}
	return block.GetTransactions(), nil
}

// getTransaction get a transaction identified by block number and index within the block
//
// getTransaction() : @blockNumber와 @txIndex에 해당하는 트랜잭션을 리턴
func (blockchain *blockchain) getTransaction(blockNumber uint64, txIndex uint64) (*protos.Transaction, error) {
	block, err := blockchain.getBlock(blockNumber)
	if err != nil {
		return nil, err
	}
	return block.GetTransactions()[txIndex], nil
}

// getTransactionByBlockHash get a transaction identified by block hash and index within the block
//
// getTransactionByBlockHash() : @blockHash와 @txIndex에 해당하는 트랜잭션을 리턴
func (blockchain *blockchain) getTransactionByBlockHash(blockHash []byte, txIndex uint64) (*protos.Transaction, error) {
	block, err := blockchain.getBlockByHash(blockHash)
	if err != nil {
		return nil, err
	}
	return block.GetTransactions()[txIndex], nil
}

// getBlockchainInfo() : 마지막 블록의 정보 리턴 ( Height, CurrentBlockHash, PreviousBlockHash )
func (blockchain *blockchain) getBlockchainInfo() (*protos.BlockchainInfo, error) {
	if blockchain.getSize() == 0 {
		return &protos.BlockchainInfo{Height: 0}, nil
	}

	lastBlock, err := blockchain.getLastBlock()
	if err != nil {
		return nil, err
	}

	info := blockchain.getBlockchainInfoForBlock(blockchain.getSize(), lastBlock)
	return info, nil
}

// getBlockchainInfoForBlock() : @height, @block에 해당하는 블록 정보 리턴 ( Height, CurrentBlockHash, PreviousBlockHash )
func (blockchain *blockchain) getBlockchainInfoForBlock(height uint64, block *protos.Block) *protos.BlockchainInfo {
	hash, _ := block.GetHash()
	info := &protos.BlockchainInfo{
		Height:            height,
		CurrentBlockHash:  hash,
		PreviousBlockHash: block.PreviousBlockHash}

	return info
}

// buildBlock() : 블록생성시 사용
//  1. addPersistenceChangesForNewBlock()에서 신규블록 생성시 사용
//  2. GetTXBatchPreviewBlockInfo()에서 TXBatch 처리후 블록정보를 미리 확인해볼때 호출해서 사용  
//
// 	@param block : 생성할 block 구조체(protobuf)
// 	@param stateHash : 이 블록의 트랜잭션들이 실행완료 된 후 state hash값
func (blockchain *blockchain) buildBlock(block *protos.Block, stateHash []byte) *protos.Block {
	block.SetPreviousBlockHash(blockchain.previousBlockHash)
	block.StateHash = stateHash 
	return block
}

// addPersistenceChangesForNewBlock() : 신규 블록 생성 및 commit 처리, blockNumber 리턴.
// Ledger.CommitTxBatch()에서 호출
func (blockchain *blockchain) addPersistenceChangesForNewBlock(ctx context.Context,
	block *protos.Block, stateHash []byte, writeBatch *gorocksdb.WriteBatch) (uint64, error) {
	block = blockchain.buildBlock(block, stateHash)
	// UTC Timestamp 기록
	if block.NonHashData == nil {
		block.NonHashData = &protos.NonHashData{LocalLedgerCommitTimestamp: util.CreateUtcTimestamp()}
	} else {
		block.NonHashData.LocalLedgerCommitTimestamp = util.CreateUtcTimestamp()
	}
	blockNumber := blockchain.size
	blockHash, err := block.GetHash()
	if err != nil {
		return 0, err
	}
	blockBytes, blockBytesErr := block.Bytes()
	if blockBytesErr != nil {
		return 0, blockBytesErr
	}
	writeBatch.PutCF(db.GetDBHandle().BlockchainCF, encodeBlockNumberDBKey(blockNumber), blockBytes)
	writeBatch.PutCF(db.GetDBHandle().BlockchainCF, blockCountKey, encodeUint64(blockNumber+1))
	if blockchain.indexer.isSynchronous() {
		blockchain.indexer.createIndexes(block, blockNumber, blockHash, writeBatch)
	}
	blockchain.lastProcessedBlock = &lastProcessedBlock{block, blockNumber, blockHash}
	return blockNumber, nil
}

// blockPersistenceStatus() : 블록이 만들어질때(commitTxBatch) 에러 발생시는 nil 리턴, 정상 커밋 처리될때 indexer생성.
// ledger.blockchain.blockPersistenceStatus 에서 호출
func (blockchain *blockchain) blockPersistenceStatus(success bool) {
	if success {
		blockchain.size++
		blockchain.previousBlockHash = blockchain.lastProcessedBlock.blockHash
		if !blockchain.indexer.isSynchronous() {
			writeBatch := gorocksdb.NewWriteBatch()
			defer writeBatch.Destroy()
			blockchain.indexer.createIndexes(blockchain.lastProcessedBlock.block,
				blockchain.lastProcessedBlock.blockNumber, blockchain.lastProcessedBlock.blockHash, writeBatch)
		}
	}
	blockchain.lastProcessedBlock = nil
}

// persistRawBlock() : raw block을 체인에 추가. 이 함수는 피어간 동기화시에만 사용해야 함.
// ledger.blockchain.persistRawBlock에서 호출
func (blockchain *blockchain) persistRawBlock(block *protos.Block, blockNumber uint64) error {
	blockBytes, blockBytesErr := block.Bytes()
	if blockBytesErr != nil {
		return blockBytesErr
	}
	writeBatch := gorocksdb.NewWriteBatch()
	defer writeBatch.Destroy()
	writeBatch.PutCF(db.GetDBHandle().BlockchainCF, encodeBlockNumberDBKey(blockNumber), blockBytes)

	blockHash, err := block.GetHash()
	if err != nil {
		return err
	}

	// Need to check as we support out of order blocks in cases such as block/state synchronization. This is
	// real blockchain height, not size.
	//
	// 블록/상태 동기화등의 경우 블록 순서 체크가 필요함.
	// 블록체인 사이즈가 아닌 블록체인 높이를 뜻함. 
	if blockchain.getSize() < blockNumber+1 {
		sizeBytes := encodeUint64(blockNumber + 1)
		writeBatch.PutCF(db.GetDBHandle().BlockchainCF, blockCountKey, sizeBytes)
		blockchain.size = blockNumber + 1
		blockchain.previousBlockHash = blockHash
	}

	if blockchain.indexer.isSynchronous() {
		blockchain.indexer.createIndexes(block, blockNumber, blockHash, writeBatch)
	}

	opt := gorocksdb.NewDefaultWriteOptions()
	defer opt.Destroy()
	err = db.GetDBHandle().DB.Write(opt, writeBatch)
	if err != nil {
		return err
	}
	return nil
}

// fetchBlockFromDB() : DB로 부터 블록높이에 해당하는 블록을 리턴.
func fetchBlockFromDB(blockNumber uint64) (*protos.Block, error) {
	blockBytes, err := db.GetDBHandle().GetFromBlockchainCF(encodeBlockNumberDBKey(blockNumber))
	if err != nil {
		return nil, err
	}
	if blockBytes == nil {
		return nil, nil
	}
	return protos.UnmarshallBlock(blockBytes)
}

// fetchBlockchainSizeFromDB() : 블록개수 리턴.
func fetchBlockchainSizeFromDB() (uint64, error) {
	bytes, err := db.GetDBHandle().GetFromBlockchainCF(blockCountKey)
	if err != nil {
		return 0, err
	}
	if bytes == nil {
		return 0, nil
	}
	return decodeToUint64(bytes), nil
}

// fetchBlockchainSizeFromSnapshot() : 블록개수 리턴 from 스냅샷, edger.GetStateSnapshot()에서 호출.
func fetchBlockchainSizeFromSnapshot(snapshot *gorocksdb.Snapshot) (uint64, error) {
	blockNumberBytes, err := db.GetDBHandle().GetFromBlockchainCFSnapshot(snapshot, blockCountKey)
	if err != nil {
		return 0, err
	}
	var blockNumber uint64
	if blockNumberBytes != nil {
		blockNumber = decodeToUint64(blockNumberBytes)
	}
	return blockNumber, nil
}

var blockCountKey = []byte("blockCount")


func encodeBlockNumberDBKey(blockNumber uint64) []byte {
	return encodeUint64(blockNumber)
}

func encodeUint64(number uint64) []byte {
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, number)
	return bytes
}

func decodeToUint64(bytes []byte) uint64 {
	return binary.BigEndian.Uint64(bytes)
}

func (blockchain *blockchain) String() string {
	var buffer bytes.Buffer
	size := blockchain.getSize()
	for i := uint64(0); i < size; i++ {
		block, blockErr := blockchain.getBlock(i)
		if blockErr != nil {
			return ""
		}
		buffer.WriteString("\n----------<block #")
		buffer.WriteString(strconv.FormatUint(i, 10))
		buffer.WriteString(">----------\n")
		buffer.WriteString(block.String())
		buffer.WriteString("\n----------<\\block #")
		buffer.WriteString(strconv.FormatUint(i, 10))
		buffer.WriteString(">----------\n")
	}
	return buffer.String()
}
