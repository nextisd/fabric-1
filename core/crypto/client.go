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

package crypto

import (
	"sync"

	"github.com/hyperledger/fabric/core/crypto/utils"
)

// Private Variables

type clientEntry struct {
	client  Client
	counter int64
}

var (
	// Map of initialized clients
	clients = make(map[string]clientEntry)

	// Sync
	clientMutex sync.Mutex
)

// Public Methods

// RegisterClient registers a client to the PKI infrastructure
// RegisterClient() Client를 PKI 인프라스트럭처에 등록
//		IN) name,  비밀번호(pwd),  등록ID, 등록비밀번호
//		OUT) 이상 발생시 errno
func RegisterClient(name string, pwd []byte, enrollID, enrollPWD string) error {
	clientMutex.Lock()
	defer clientMutex.Unlock()

	log.Infof("Registering client [%s] with name [%s]...", enrollID, name)

	if _, ok := clients[name]; ok {
		log.Infof("Registering client [%s] with name [%s]...done. Already initialized.", enrollID, name)

		return nil
	}

	client := newClient()
	if err := client.register(name, pwd, enrollID, enrollPWD); err != nil {
		if err != utils.ErrAlreadyRegistered && err != utils.ErrAlreadyInitialized {
			log.Errorf("Failed registering client [%s] with name [%s] [%s].", enrollID, name, err)
			return err
		}
		log.Infof("Registering client [%s] with name [%s]...done. Already registered or initiliazed.", enrollID, name)
	}
	err := client.close()
	if err != nil {
		// It is not necessary to report this error to the caller
		log.Warningf("Registering client [%s] with name [%s]. Failed closing [%s].", enrollID, name, err)
	}

	log.Infof("Registering client [%s] with name [%s]...done!", enrollID, name)

	return nil
}

// InitClient initializes a client named name with password pwd
// InitClient() a client 초기화
//		IN) name, 비밀번호
//		OUT)	client, error
func InitClient(name string, pwd []byte) (Client, error) {
	clientMutex.Lock()
	defer clientMutex.Unlock()

	log.Infof("Initializing client [%s]...", name)

	if entry, ok := clients[name]; ok {
		log.Infof("Client already initiliazied [%s]. Increasing counter from [%d]", name, clients[name].counter)
		entry.counter++
		clients[name] = entry

		return clients[name].client, nil
	}

	client := newClient()
	if err := client.init(name, pwd); err != nil {
		log.Errorf("Failed client initialization [%s]: [%s].", name, err)

		return nil, err
	}

	clients[name] = clientEntry{client, 1}
	log.Infof("Initializing client [%s]...done!", name)

	return client, nil
}

// CloseClient releases all the resources allocated by clients
// CloseClient() Client에 의해 할당된 모든 리소스를 해제
//		IN)		client
//		OUT)	error
func CloseClient(client Client) error {
	clientMutex.Lock()
	defer clientMutex.Unlock()

	return closeClientInternal(client, false)
}

// CloseAllClients closes all the clients initialized so far
// CloseAllClients() 이제까지 초기화한 Client 모두를 Close한다.
//		IN) Nothing
//		OUT)	정상/비정상		error들
func CloseAllClients() (bool, []error) {
	clientMutex.Lock()
	defer clientMutex.Unlock()

	log.Info("Closing all clients...")

	errs := make([]error, len(clients))
	for _, value := range clients {
		err := closeClientInternal(value.client, true)

		errs = append(errs, err)
	}

	log.Info("Closing all clients...done!")

	return len(errs) != 0, errs
}

// Private Methods

func newClient() *clientImpl {
	return &clientImpl{&nodeImpl{}, nil, nil, nil, nil}
}

// closeClientInternal() 내부의 Client Clode
//		IN) client, force(True/False)
//		OUT) error
func closeClientInternal(client Client, force bool) error {
	if client == nil {
		return utils.ErrNilArgument
	}

	name := client.GetName()
	log.Infof("Closing client [%s]...", name)
	entry, ok := clients[name]
	if !ok {
		return utils.ErrInvalidReference
	}
	if entry.counter == 1 || force {
		defer delete(clients, name)
		err := clients[name].client.(*clientImpl).close()
		log.Debugf("Closing client [%s]...cleanup! [%s].", name, utils.ErrToString(err))

		return err
	}

	// decrease counter
	entry.counter--
	clients[name] = entry
	log.Debugf("Closing client [%s]...decreased counter at [%d].", name, clients[name].counter)

	return nil
}
