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

package db

import (
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/spf13/viper"
	"github.com/tecbot/gorocksdb"
)

var dbLogger = logging.MustGetLogger("db")

const blockchainCF = "blockchainCF"
const stateCF = "stateCF"
const stateDeltaCF = "stateDeltaCF"
const indexesCF = "indexesCF"
const persistCF = "persistCF"

var columnfamilies = []string{
	blockchainCF, // blocks of the block chain
	stateCF,      // world state
	stateDeltaCF, // open transaction state
	indexesCF,    // tx uuid -> blockno
	persistCF,    // persistent per-peer state (consensus)
}

// OpenchainDB encapsulates rocksdb's structures
type OpenchainDB struct {
	DB           *gorocksdb.DB
	BlockchainCF *gorocksdb.ColumnFamilyHandle
	StateCF      *gorocksdb.ColumnFamilyHandle
	StateDeltaCF *gorocksdb.ColumnFamilyHandle
	IndexesCF    *gorocksdb.ColumnFamilyHandle
	PersistCF    *gorocksdb.ColumnFamilyHandle
}

var openchainDB = create()

// Create create an openchainDB instance
// create() openchainDB instance 생성
func create() *OpenchainDB {
	return &OpenchainDB{}
}

// GetDBHandle gets an opened openchainDB singleton. Note that method Start must always be invoked before this method.
// GetDBHandle() 하나의 opened openchainDB 취득(주: 메소드의 시작은 항상 이 메소드 전에 호출되어야 한다)
func GetDBHandle() *OpenchainDB {
	return openchainDB
}

// Start the db, init the openchainDB instance and open the db. Note this method has no guarantee correct behavior concurrent invocation.
// openchainDB Start
func Start() {
	openchainDB.open()
}

// Stop the db. Note this method has no guarantee correct behavior concurrent invocation.
// openchainDB Stop
func Stop() {
	openchainDB.close()
}

// GetFromBlockchainCF get value for given key from column family - blockchainCF
// GetFromBlockchainCF() Column Family로부터 주어진 Key에 대한 Value 취득
func (openchainDB *OpenchainDB) GetFromBlockchainCF(key []byte) ([]byte, error) {
	return openchainDB.Get(openchainDB.BlockchainCF, key)
}

// GetFromBlockchainCFSnapshot get value for given key from column family in a DB snapshot - blockchainCF
// GetFromBlockchainCFSnapshot() DB snapshot에 있는 Column Family로부터 주어진 Key에 대한 Value 취득
func (openchainDB *OpenchainDB) GetFromBlockchainCFSnapshot(snapshot *gorocksdb.Snapshot, key []byte) ([]byte, error) {
	return openchainDB.getFromSnapshot(snapshot, openchainDB.BlockchainCF, key)
}

// GetFromStateCF get value for given key from column family - stateCF
func (openchainDB *OpenchainDB) GetFromStateCF(key []byte) ([]byte, error) {
	return openchainDB.Get(openchainDB.StateCF, key)
}

// GetFromStateDeltaCF get value for given key from column family - stateDeltaCF
func (openchainDB *OpenchainDB) GetFromStateDeltaCF(key []byte) ([]byte, error) {
	return openchainDB.Get(openchainDB.StateDeltaCF, key)
}

// GetFromIndexesCF get value for given key from column family - indexCF
func (openchainDB *OpenchainDB) GetFromIndexesCF(key []byte) ([]byte, error) {
	return openchainDB.Get(openchainDB.IndexesCF, key)
}

// GetBlockchainCFIterator get iterator for column family - blockchainCF
func (openchainDB *OpenchainDB) GetBlockchainCFIterator() *gorocksdb.Iterator {
	return openchainDB.GetIterator(openchainDB.BlockchainCF)
}

// GetStateCFIterator get iterator for column family - stateCF
func (openchainDB *OpenchainDB) GetStateCFIterator() *gorocksdb.Iterator {
	return openchainDB.GetIterator(openchainDB.StateCF)
}

// GetStateCFSnapshotIterator get iterator for column family - stateCF. This iterator
// is based on a snapshot and should be used for long running scans, such as
// reading the entire state. Remember to call iterator.Close() when you are done.
func (openchainDB *OpenchainDB) GetStateCFSnapshotIterator(snapshot *gorocksdb.Snapshot) *gorocksdb.Iterator {
	return openchainDB.getSnapshotIterator(snapshot, openchainDB.StateCF)
}

// GetStateDeltaCFIterator get iterator for column family - stateDeltaCF
func (openchainDB *OpenchainDB) GetStateDeltaCFIterator() *gorocksdb.Iterator {
	return openchainDB.GetIterator(openchainDB.StateDeltaCF)
}

// GetSnapshot returns a point-in-time view of the DB. You MUST call snapshot.Release()
// when you are done with the snapshot.
func (openchainDB *OpenchainDB) GetSnapshot() *gorocksdb.Snapshot {
	return openchainDB.DB.NewSnapshot()
}

func getDBPath() string {
	dbPath := viper.GetString("peer.fileSystemPath")
	if dbPath == "" {
		panic("DB path not specified in configuration file. Please check that property 'peer.fileSystemPath' is set")
	}
	if !strings.HasSuffix(dbPath, "/") {
		dbPath = dbPath + "/"
	}
	return dbPath + "db"
}

// Open open underlying rocksdb
// Rocksdb하에서 Open
func (openchainDB *OpenchainDB) open() {
	dbPath := getDBPath()
	missing, err := dirMissingOrEmpty(dbPath)
	if err != nil {
		panic(fmt.Sprintf("Error while trying to open DB: %s", err))
	}
	dbLogger.Debugf("Is db path [%s] empty [%t]", dbPath, missing)

	if missing {
		err = os.MkdirAll(path.Dir(dbPath), 0755)
		if err != nil {
			panic(fmt.Sprintf("Error making directory path [%s]: %s", dbPath, err))
		}
	}

	opts := gorocksdb.NewDefaultOptions()
	defer opts.Destroy()

	opts.SetCreateIfMissing(missing)
	opts.SetCreateIfMissingColumnFamilies(true)

	cfNames := []string{"default"}
	cfNames = append(cfNames, columnfamilies...)
	var cfOpts []*gorocksdb.Options
	for range cfNames {
		cfOpts = append(cfOpts, opts)
	}

	db, cfHandlers, err := gorocksdb.OpenDbColumnFamilies(opts, dbPath, cfNames, cfOpts)

	if err != nil {
		panic(fmt.Sprintf("Error opening DB: %s", err))
	}

	openchainDB.DB = db
	openchainDB.BlockchainCF = cfHandlers[1]
	openchainDB.StateCF = cfHandlers[2]
	openchainDB.StateDeltaCF = cfHandlers[3]
	openchainDB.IndexesCF = cfHandlers[4]
	openchainDB.PersistCF = cfHandlers[5]
}

// Close releases all column family handles and closes rocksdb
func (openchainDB *OpenchainDB) close() {
	openchainDB.BlockchainCF.Destroy()
	openchainDB.StateCF.Destroy()
	openchainDB.StateDeltaCF.Destroy()
	openchainDB.IndexesCF.Destroy()
	openchainDB.PersistCF.Destroy()
	openchainDB.DB.Close()
}

// DeleteState delets ALL state keys/values from the DB. This is generally
// only used during state synchronization when creating a new state from
// a snapshot.
// DB에서 모든 상태 Key/Value들을 삭제(이 함수는 Snapshot으로부터 신규 state를 만들때 State 동기화 동안에만 일반적으로 사용된다.(?))
func (openchainDB *OpenchainDB) DeleteState() error {
	err := openchainDB.DB.DropColumnFamily(openchainDB.StateCF)
	if err != nil {
		dbLogger.Errorf("Error dropping state CF: %s", err)
		return err
	}
	err = openchainDB.DB.DropColumnFamily(openchainDB.StateDeltaCF)
	if err != nil {
		dbLogger.Errorf("Error dropping state delta CF: %s", err)
		return err
	}
	opts := gorocksdb.NewDefaultOptions()
	defer opts.Destroy()
	openchainDB.StateCF, err = openchainDB.DB.CreateColumnFamily(opts, stateCF)
	if err != nil {
		dbLogger.Errorf("Error creating state CF: %s", err)
		return err
	}
	openchainDB.StateDeltaCF, err = openchainDB.DB.CreateColumnFamily(opts, stateDeltaCF)
	if err != nil {
		dbLogger.Errorf("Error creating state delta CF: %s", err)
		return err
	}
	return nil
}

// Get returns the valud for the given column family and key
// Get() 주어진 CF와 KEY에 대한 Value를 Return.
func (openchainDB *OpenchainDB) Get(cfHandler *gorocksdb.ColumnFamilyHandle, key []byte) ([]byte, error) {
	opt := gorocksdb.NewDefaultReadOptions()
	defer opt.Destroy()
	slice, err := openchainDB.DB.GetCF(opt, cfHandler, key)
	if err != nil {
		dbLogger.Errorf("Error while trying to retrieve key: %s", key)
		return nil, err
	}
	defer slice.Free()
	if slice.Data() == nil {
		return nil, nil
	}
	data := makeCopy(slice.Data())
	return data, nil
}

// Put saves the key/value in the given column family
// Put() 주어진 CF에서 Key와 Value 저장
func (openchainDB *OpenchainDB) Put(cfHandler *gorocksdb.ColumnFamilyHandle, key []byte, value []byte) error {
	opt := gorocksdb.NewDefaultWriteOptions()
	defer opt.Destroy()
	err := openchainDB.DB.PutCF(opt, cfHandler, key, value)
	if err != nil {
		dbLogger.Errorf("Error while trying to write key: %s", key)
		return err
	}
	return nil
}

// Delete delets the given key in the specified column family
// Delete() 특정 CD에 있는 KEY 삭제
func (openchainDB *OpenchainDB) Delete(cfHandler *gorocksdb.ColumnFamilyHandle, key []byte) error {
	opt := gorocksdb.NewDefaultWriteOptions()
	defer opt.Destroy()
	err := openchainDB.DB.DeleteCF(opt, cfHandler, key)
	if err != nil {
		dbLogger.Errorf("Error while trying to delete key: %s", key)
		return err
	}
	return nil
}

func (openchainDB *OpenchainDB) getFromSnapshot(snapshot *gorocksdb.Snapshot, cfHandler *gorocksdb.ColumnFamilyHandle, key []byte) ([]byte, error) {
	opt := gorocksdb.NewDefaultReadOptions()
	defer opt.Destroy()
	opt.SetSnapshot(snapshot)
	slice, err := openchainDB.DB.GetCF(opt, cfHandler, key)
	if err != nil {
		dbLogger.Errorf("Error while trying to retrieve key: %s", key)
		return nil, err
	}
	defer slice.Free()
	data := append([]byte(nil), slice.Data()...)
	return data, nil
}

// GetIterator returns an iterator for the given column family
// GetIterator() 주어진 CF에 대한 신규 Iterator 취득
func (openchainDB *OpenchainDB) GetIterator(cfHandler *gorocksdb.ColumnFamilyHandle) *gorocksdb.Iterator {
	opt := gorocksdb.NewDefaultReadOptions()
	opt.SetFillCache(true)
	defer opt.Destroy()
	return openchainDB.DB.NewIteratorCF(opt, cfHandler)
}

func (openchainDB *OpenchainDB) getSnapshotIterator(snapshot *gorocksdb.Snapshot, cfHandler *gorocksdb.ColumnFamilyHandle) *gorocksdb.Iterator {
	opt := gorocksdb.NewDefaultReadOptions()
	defer opt.Destroy()
	opt.SetSnapshot(snapshot)
	iter := openchainDB.DB.NewIteratorCF(opt, cfHandler)
	return iter
}

func dirMissingOrEmpty(path string) (bool, error) {
	dirExists, err := dirExists(path)
	if err != nil {
		return false, err
	}
	if !dirExists {
		return true, nil
	}

	dirEmpty, err := dirEmpty(path)
	if err != nil {
		return false, err
	}
	if dirEmpty {
		return true, nil
	}
	return false, nil
}

func dirExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func dirEmpty(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Readdir(1)
	if err == io.EOF {
		return true, nil
	}
	return false, err
}

func makeCopy(src []byte) []byte {
	dest := make([]byte, len(src))
	copy(dest, src)
	return dest
}
