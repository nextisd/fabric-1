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
	"crypto/x509"

	"github.com/hyperledger/fabric/core/crypto/attributes"
	"github.com/hyperledger/fabric/core/crypto/utils"
)

type tCert interface {
	//GetCertificate returns the x509 certificate of the TCert.
	GetCertificate() *x509.Certificate

	//GetPreK0 returns the PreK0 of the TCert. This key is used to derivate attributes keys.
	GetPreK0() []byte

	//Sign signs a msg with the TCert secret key an returns the signature.
	Sign(msg []byte) ([]byte, error)

	//Verify verifies signature and message using the TCert public key.
	Verify(signature, msg []byte) error

	//GetKForAttribute derives the key for a specific attribute name.
	GetKForAttribute(attributeName string) ([]byte, error)
}

type tCertImpl struct {
	client *clientImpl
	cert   *x509.Certificate
	sk     interface{}
	preK0  []byte
}

//GetCertificate returns the x509 certificate of the TCert.
//GetCertificate() TCert의 x509인증서를 Return
func (tCert *tCertImpl) GetCertificate() *x509.Certificate {
	return tCert.cert
}

//GetPreK0 returns the PreK0 of the TCert. This key is used to derivate attributes keys.
//GetPreK0() TCert의 PreK0를 return. 이 키는 파생된 속성키로 사용된다.
func (tCert *tCertImpl) GetPreK0() []byte {
	return tCert.preK0
}

//Sign signs a msg with the TCert secret key an returns the signature.
//Sign()은 전문을 서명한다.
func (tCert *tCertImpl) Sign(msg []byte) ([]byte, error) {
	if tCert.sk == nil {
		return nil, utils.ErrNilArgument
	}

	return tCert.client.sign(tCert.sk, msg)
}

//Verify verifies signature and message using the TCert public key.
//Verify()는 TCert Public카를 사용하는 메시지와 서명을 검증한다.
func (tCert *tCertImpl) Verify(signature, msg []byte) (err error) {
	ok, err := tCert.client.verify(tCert.cert.PublicKey, msg, signature)
	if err != nil {
		return
	}
	if !ok {
		return utils.ErrInvalidSignature
	}
	return
}

//GetKForAttribute derives the key for a specific attribute name.
//GetKForAttribute()는 특정 속성명에 대한 Key를 생성한다.
func (tCert *tCertImpl) GetKForAttribute(attributeName string) ([]byte, error) {
	if tCert.preK0 == nil {
		return nil, utils.ErrNilArgument
	}

	return attributes.GetKForAttribute(attributeName, tCert.preK0, tCert.GetCertificate())
}
