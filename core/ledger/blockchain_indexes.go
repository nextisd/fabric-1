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

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/core/db"
	"github.com/hyperledger/fabric/protos"
	"github.com/op/go-logging"
	"github.com/tecbot/gorocksdb"
)

var indexLogger = logging.MustGetLogger("indexes")
var prefixBlockHashKey = byte(1)
var prefixTxIDKey = byte(2)
var prefixAddressBlockNumCompositeKey = byte(3)

// blockchain_indexes.go       : blockchain indexer sync 구현
// blockchain_indexes_async.go : blockchain indexer async 구현
type blockchainIndexer interface {
	isSynchronous() bool
	start(blockchain *blockchain) error
	createIndexes(block *protos.Block, blockNumber uint64, blockHash []byte, writeBatch *gorocksdb.WriteBatch) error
	fetchBlockNumberByBlockHash(blockHash []byte) (uint64, error)
	fetchTransactionIndexByID(txID string) (uint64, uint64, error)
	stop()
}

// Implementation for sync indexer
//
// blockchain sync indexer 구현
type blockchainIndexerSync struct {
}

func newBlockchainIndexerSync() *blockchainIndexerSync {
	return &blockchainIndexerSync{}
}

func (indexer *blockchainIndexerSync) isSynchronous() bool {
	return true
}

func (indexer *blockchainIndexerSync) start(blockchain *blockchain) error {
	return nil
}

func (indexer *blockchainIndexerSync) createIndexes(
	block *protos.Block, blockNumber uint64, blockHash []byte, writeBatch *gorocksdb.WriteBatch) error {
	return addIndexDataForPersistence(block, blockNumber, blockHash, writeBatch)
}

func (indexer *blockchainIndexerSync) fetchBlockNumberByBlockHash(blockHash []byte) (uint64, error) {
	return fetchBlockNumberByBlockHashFromDB(blockHash)
}

func (indexer *blockchainIndexerSync) fetchTransactionIndexByID(txID string) (uint64, uint64, error) {
	return fetchTransactionIndexByIDFromDB(txID)
}

func (indexer *blockchainIndexerSync) stop() {
	return
}

// Functions for persisting and retrieving index data
//
// addIndexDataForPersistence() : 인덱스 데이터를 유지하고 검색 기능 구현.
func addIndexDataForPersistence(block *protos.Block, blockNumber uint64, blockHash []byte, writeBatch *gorocksdb.WriteBatch) error {
	openchainDB := db.GetDBHandle()
	// IndexesCF : 인덱스 컬럼패밀리 핸들러
	// 컬럼패밀리(column family) : 하나의 key에 여러개의 컬럼이 달려 있는 형태로서, RDBMS의 테이블과 유사.
	//
	// e.g. 1.컬럼 :	key-value 로 이루어진 데이터 구조체
	//					{ name:"James", asset:"Money" }
	//
	//      2.슈퍼컬럼 : 컬럼 구조체 안에 다시 컬럼이 들어가 있는 구조체.
	//					{ name: { first:"Michael", last:"Jackson" }
	//
	//      3.컬럼패밀리 : PersonalInfo={
	//						Info1={name:"James", age:"20"}
	//						Info2={name:"Smith", age:"25", email:"smith@smith.com"}
	//						Info3={name:"Jack",  age:"30", address:"Korea Seoul"}
	//					 }
	//
	//		==> 	컬럼패밀리는 PersonalInfo, 각 행(row)에 대한 key들은 Info1,Info2,Info3
	//			각 행들은 여러개의 컬럼으로 구성되어 있음.
	//
	//	*fabric/core/db/db.go
	//	var columnfamilies = []string{
	//		blockchainCF, // blocks of the block chain
	//		stateCF,      // world state
	//		stateDeltaCF, // open transaction state
	//		indexesCF,    // tx uuid -> blockno
	//		persistCF,    // persistent per-peer state (consensus)
	//  }

	cf := openchainDB.IndexesCF

	// add blockhash -> blockNumber
	//
	// blockHash(key),blockNumber(value)를 indexesCF 컬럼패밀리에 추가
	indexLogger.Debugf("Indexing block number [%d] by hash = [%x]", blockNumber, blockHash)

	// writeBatch.putCF() 함수 처리 인자 참고.
	// endor/github.com/tecbot/gorocksdb/write_batch.go :
	//	==> rocksdb_writebatch_put_cf(wb.c, cf.c, cKey, C.size_t(len(key)), cValue, C.size_t(len(value)))
	//	==> rocksdb_writebatch_put_cf(batch: DBWriteBatch, cf: DBCFHandle, key: *const u8, klen: size_t, val: *const u8, vlen: size_t)
	writeBatch.PutCF(cf, encodeBlockHashKey(blockHash), encodeBlockNumber(blockNumber))

	addressToTxIndexesMap := make(map[string][]uint64)
	addressToChaincodeIDsMap := make(map[string][]*protos.ChaincodeID)

	transactions := block.GetTransactions()
	// 블록내의 모든 트랜잭션을 읽어서 처리
	for txIndex, tx := range transactions {
		// add TxID -> (blockNumber,indexWithinBlock)
		//
		// 트랜잭션들을 모두 인덱싱 : Txid(key),Blocknumber+txIndex(value)를 indexesCF에 추가
		writeBatch.PutCF(cf, encodeTxIDKey(tx.Txid), encodeBlockNumTxIndex(blockNumber, uint64(txIndex)))

		// tx index Map 생성 및 추가
		txExecutingAddress := getTxExecutingAddress(tx) // "address1"로 하드코딩되어 있음...
		addressToTxIndexesMap[txExecutingAddress] = append(addressToTxIndexesMap[txExecutingAddress], uint64(txIndex))

		switch tx.Type {
		case protos.Transaction_CHAINCODE_DEPLOY, protos.Transaction_CHAINCODE_INVOKE:
			authroizedAddresses, chaincodeID := getAuthorisedAddresses(tx) // "address1","address2" 하드코딩되어 있음...
			for _, authroizedAddress := range authroizedAddresses {
				// ChaincodeID Map 생성
				addressToChaincodeIDsMap[authroizedAddress] = append(addressToChaincodeIDsMap[authroizedAddress], chaincodeID)
			}
		}
	}
	for address, txsIndexes := range addressToTxIndexesMap {
		// address+block번호(key) txIndex(value)를 IndexesCF에 추가
		writeBatch.PutCF(cf, encodeAddressBlockNumCompositeKey(address, blockNumber), encodeListTxIndexes(txsIndexes))
	}
	return nil
}

// fetchBlockNumberByBlockHashFromDB() : blockHash에 해당하는 블록의 blockNumber값 리턴
func fetchBlockNumberByBlockHashFromDB(blockHash []byte) (uint64, error) {
	indexLogger.Debugf("fetchBlockNumberByBlockHashFromDB() for blockhash [%x]", blockHash)
	blockNumberBytes, err := db.GetDBHandle().GetFromIndexesCF(encodeBlockHashKey(blockHash))
	if err != nil {
		return 0, err
	}
	indexLogger.Debugf("blockNumberBytes for blockhash [%x] is [%x]", blockHash, blockNumberBytes)
	if len(blockNumberBytes) == 0 {
		return 0, newLedgerError(ErrorTypeBlockNotFound, fmt.Sprintf("No block indexed with block hash [%x]", blockHash))
	}
	blockNumber := decodeBlockNumber(blockNumberBytes)
	return blockNumber, nil
}

// fetchTransactionIndexByIDFromDB() : txID에 해당하는 blockNum과 txIndex를 리턴
func fetchTransactionIndexByIDFromDB(txID string) (uint64, uint64, error) {
	blockNumTxIndexBytes, err := db.GetDBHandle().GetFromIndexesCF(encodeTxIDKey(txID))
	if err != nil {
		return 0, 0, err
	}
	if blockNumTxIndexBytes == nil {
		return 0, 0, ErrResourceNotFound
	}
	return decodeBlockNumTxIndex(blockNumTxIndexBytes)
}

func getTxExecutingAddress(tx *protos.Transaction) string {
	// TODO Fetch address form tx
	//
	// TODO tx 실행 주소 리턴, 미개발?
	return "address1"
}

func getAuthorisedAddresses(tx *protos.Transaction) ([]string, *protos.ChaincodeID) {
	// TODO fetch address from chaincode deployment tx
	// TODO this method should also return error
	//
	// 미개발?
	data := tx.ChaincodeID
	cID := &protos.ChaincodeID{}
	err := proto.Unmarshal(data, cID)
	if err != nil {
		return nil, nil
	}
	return []string{"address1", "address2"}, cID
}

// functions for encoding/decoding db keys/values for index data
// encode / decode BlockNumber
func encodeBlockNumber(blockNumber uint64) []byte {
	return proto.EncodeVarint(blockNumber)
}

func decodeBlockNumber(blockNumberBytes []byte) (blockNumber uint64) {
	blockNumber, _ = proto.DecodeVarint(blockNumberBytes)
	return
}

// encode / decode BlockNumTxIndex
func encodeBlockNumTxIndex(blockNumber uint64, txIndexInBlock uint64) []byte {
	b := proto.NewBuffer([]byte{})
	b.EncodeVarint(blockNumber)
	b.EncodeVarint(txIndexInBlock)
	return b.Bytes()
}

func decodeBlockNumTxIndex(bytes []byte) (blockNum uint64, txIndex uint64, err error) {
	b := proto.NewBuffer(bytes)
	blockNum, err = b.DecodeVarint()
	if err != nil {
		return
	}
	txIndex, err = b.DecodeVarint()
	if err != nil {
		return
	}
	return
}

// encode BlockHashKey
func encodeBlockHashKey(blockHash []byte) []byte {
	return prependKeyPrefix(prefixBlockHashKey, blockHash)
}

// encode TxIDKey
func encodeTxIDKey(txID string) []byte {
	return prependKeyPrefix(prefixTxIDKey, []byte(txID))
}

func encodeAddressBlockNumCompositeKey(address string, blockNumber uint64) []byte {
	b := proto.NewBuffer([]byte{prefixAddressBlockNumCompositeKey})
	b.EncodeRawBytes([]byte(address))
	b.EncodeVarint(blockNumber)
	return b.Bytes()
}

func encodeListTxIndexes(listTx []uint64) []byte {
	b := proto.NewBuffer([]byte{})
	for i := range listTx {
		b.EncodeVarint(listTx[i])
	}
	return b.Bytes()
}

func prependKeyPrefix(prefix byte, key []byte) []byte {
	modifiedKey := []byte{}
	modifiedKey = append(modifiedKey, prefix)
	modifiedKey = append(modifiedKey, key...)
	return modifiedKey
}
