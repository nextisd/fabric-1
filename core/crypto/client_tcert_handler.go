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
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/hyperledger/fabric/core/crypto/utils"
	obc "github.com/hyperledger/fabric/protos"
)

type tCertHandlerImpl struct {
	client *clientImpl

	tCert tCert
}

type tCertTransactionHandlerImpl struct {
	tCertHandler *tCertHandlerImpl

	nonce   []byte
	binding []byte
}

func (handler *tCertHandlerImpl) init(client *clientImpl, tCert tCert) error {
	handler.client = client
	handler.tCert = tCert

	return nil
}

// GetCertificate returns the TCert DER
// GetCertificate()는 TCert DER를 Return
func (handler *tCertHandlerImpl) GetCertificate() []byte {
	return utils.Clone(handler.tCert.GetCertificate().Raw)
}

// Sign signs msg using the signing key corresponding to this TCert
// Sign()은 이TCert에 상응하는 서명키를 사용하는 전문을 서명한다(?).
func (handler *tCertHandlerImpl) Sign(msg []byte) ([]byte, error) {
	return handler.tCert.Sign(msg)
}

// Verify verifies msg using the verifying key corresponding to this TCert
// Verify()은 이 TCert에 대응하는 검증키를 사용하는 전문을 검증한다.
func (handler *tCertHandlerImpl) Verify(signature []byte, msg []byte) error {
	return handler.tCert.Verify(signature, msg)
}

// GetTransactionHandler returns the transaction handler relative to this certificate
// GetTransactionHandler()는 이 인증서와 관련이 있는 Tx Handler를 Return
func (handler *tCertHandlerImpl) GetTransactionHandler() (TransactionHandler, error) {
	txHandler := &tCertTransactionHandlerImpl{}
	err := txHandler.init(handler)
	if err != nil {
		handler.client.Errorf("Failed initiliazing transaction handler [%s]", err)

		return nil, err
	}

	return txHandler, nil
}

func (handler *tCertTransactionHandlerImpl) init(tCertHandler *tCertHandlerImpl) error {
	nonce, err := tCertHandler.client.createTransactionNonce()
	if err != nil {
		tCertHandler.client.Errorf("Failed initiliazing transaction handler [%s]", err)

		return err
	}

	handler.tCertHandler = tCertHandler
	handler.nonce = nonce
	handler.binding = primitives.Hash(append(handler.tCertHandler.tCert.GetCertificate().Raw, nonce...))

	return nil
}

// GetCertificateHandler returns the certificate handler relative to the certificate mapped to this transaction
// GetCertificateHandler()는 Tx와 매핑되는 인증서와 관련한 인증서Handler를 Return
func (handler *tCertTransactionHandlerImpl) GetCertificateHandler() (CertificateHandler, error) {
	return handler.tCertHandler, nil
}

// GetBinding returns an Binding to the underlying transaction layer
// GetBinding()은 Tx레이어 하에서 Binding을 return
func (handler *tCertTransactionHandlerImpl) GetBinding() ([]byte, error) {
	return utils.Clone(handler.binding), nil
}

// NewChaincodeDeployTransaction is used to deploy chaincode.
// NewChaincodeDeployTransaction()은 Chaincode를 Deploy하는데 사용
func (handler *tCertTransactionHandlerImpl) NewChaincodeDeployTransaction(chaincodeDeploymentSpec *obc.ChaincodeDeploymentSpec, uuid string, attributeNames ...string) (*obc.Transaction, error) {
	return handler.tCertHandler.client.newChaincodeDeployUsingTCert(chaincodeDeploymentSpec, uuid, attributeNames, handler.tCertHandler.tCert, handler.nonce)
}

// NewChaincodeExecute is used to execute chaincode's functions.
// NewChaincodeExecute()은 Chaincode 기능들을 실행하는데 사용
func (handler *tCertTransactionHandlerImpl) NewChaincodeExecute(chaincodeInvocation *obc.ChaincodeInvocationSpec, uuid string, attributeNames ...string) (*obc.Transaction, error) {
	return handler.tCertHandler.client.newChaincodeExecuteUsingTCert(chaincodeInvocation, uuid, attributeNames, handler.tCertHandler.tCert, handler.nonce)
}

// NewChaincodeQuery is used to query chaincode's functions.
// NewChaincodeQuery()는 Chaincode 기능들을 조회하는데 사용
func (handler *tCertTransactionHandlerImpl) NewChaincodeQuery(chaincodeInvocation *obc.ChaincodeInvocationSpec, uuid string, attributeNames ...string) (*obc.Transaction, error) {
	return handler.tCertHandler.client.newChaincodeQueryUsingTCert(chaincodeInvocation, uuid, attributeNames, handler.tCertHandler.tCert, handler.nonce)
}
