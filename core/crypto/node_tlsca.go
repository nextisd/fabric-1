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
	membersrvc "github.com/hyperledger/fabric/membersrvc/protos"

	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/hyperledger/fabric/core/util"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

// retrieveTLSCertificate() TLS 인증서 찾기
func (node *nodeImpl) retrieveTLSCertificate(id, affiliation string) error {
	// TLS 인증서 파일에 인증서 확인
	if !node.ks.certMissing(node.conf.getTLSCertFilename()) {
		return nil
	}

	// TLSCA에서 TLS인증서의 Key와 인증서 취득
	key, tlsCertRaw, err := node.getTLSCertificateFromTLSCA(id, affiliation)
	if err != nil {
		node.Errorf("Failed getting tls certificate [id=%s] %s", id, err)

		return err
	}
	node.Debugf("TLS Cert [% x]", tlsCertRaw)

	node.Debugf("Storing TLS key and certificate for user [%s]...", id)

	// Store tls key.
	if err := node.ks.storePrivateKeyInClear(node.conf.getTLSKeyFilename(), key); err != nil {
		node.Errorf("Failed storing tls key [id=%s]: %s", id, err)
		return err
	}

	// Store tls cert
	if err := node.ks.storeCert(node.conf.getTLSCertFilename(), tlsCertRaw); err != nil {
		node.Errorf("Failed storing tls certificate [id=%s]: %s", id, err)
		return err
	}

	return nil
}

// deleteTLSCertificate() TLS 인증서 삭제
func (node *nodeImpl) deleteTLSCertificate(id, affiliation string) error {
	// Delete Private Key
	if err := node.ks.deletePrivateKeyInClear(node.conf.getTLSKeyFilename()); err != nil {
		node.Errorf("Failed deleting tls key [id=%s]: %s", id, err)
		return err
	}

	// Delete tls cert
	if err := node.ks.deleteCert(node.conf.getTLSCertFilename()); err != nil {
		node.Errorf("Failed deleting tls certificate [id=%s]: %s", id, err)
		return err
	}

	return nil
}

// loadTLSCertificate() TLS 인증서 Load(X509 & DER 인증서)
func (node *nodeImpl) loadTLSCertificate() error {
	node.Debug("Loading tls certificate...")

	cert, _, err := node.ks.loadCertX509AndDer(node.conf.getTLSCertFilename())
	if err != nil {
		node.Errorf("Failed parsing tls certificate [%s].", err.Error())

		return err
	}
	node.tlsCert = cert

	return nil
}

// loadTLSCACertsChain() TLS 인증체인 Load
func (node *nodeImpl) loadTLSCACertsChain() error {
	if node.conf.isTLSEnabled() {
		node.Debug("Loading TLSCA certificates chain...")

		// External PEM 인증서 Load
		pem, err := node.ks.loadExternalCert(node.conf.getTLSCACertsExternalPath())
		if err != nil {
			node.Errorf("Failed loading TLSCA certificates chain [%s].", err.Error())

			return err
		}

		// PEM으로부터 인증서 추가
		ok := node.tlsCertPool.AppendCertsFromPEM(pem)
		if !ok {
			node.Error("Failed appending TLSCA certificates chain.")

			return errors.New("Failed appending TLSCA certificates chain.")
		}

		node.Debug("Loading TLSCA certificates chain...done")

	} else {
		node.Debug("TLS is disabled!!!")
	}

	return nil
}

// getTLSCertificateFromTLSCA() TLSCA 에서 TLS인증서 취득
func (node *nodeImpl) getTLSCertificateFromTLSCA(id, affiliation string) (interface{}, []byte, error) {
	node.Debug("getTLSCertificate...")

	priv, err := primitives.NewECDSAKey()

	if err != nil {
		node.Errorf("Failed generating key: %s", err)

		return nil, nil, err
	}

	uuid := util.GenerateUUID()

	// Prepare the request
	pubraw, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	now := time.Now()
	timestamp := timestamp.Timestamp{Seconds: int64(now.Second()), Nanos: int32(now.Nanosecond())}

	req := &membersrvc.TLSCertCreateReq{
		Ts: &timestamp,
		Id: &membersrvc.Identity{Id: id + "-" + uuid},
		Pub: &membersrvc.PublicKey{
			Type: membersrvc.CryptoType_ECDSA,
			Key:  pubraw,
		}, Sig: nil}
	rawreq, _ := proto.Marshal(req)
	r, s, err := ecdsa.Sign(rand.Reader, priv, primitives.Hash(rawreq))
	if err != nil {
		panic(err)
	}
	R, _ := r.MarshalText()
	S, _ := s.MarshalText()
	req.Sig = &membersrvc.Signature{Type: membersrvc.CryptoType_ECDSA, R: R, S: S}

	pbCert, err := node.callTLSCACreateCertificate(context.Background(), req)
	if err != nil {
		node.Errorf("Failed requesting tls certificate: %s", err)

		return nil, nil, err
	}

	node.Debug("Verifing tls certificate...")

	tlsCert, err := primitives.DERToX509Certificate(pbCert.Cert.Cert)
	certPK := tlsCert.PublicKey.(*ecdsa.PublicKey)
	primitives.VerifySignCapability(priv, certPK)

	node.Debug("Verifing tls certificate...done!")

	return priv, pbCert.Cert.Cert, nil
}

// getTLSCAClient() TLSCA Client 취득
func (node *nodeImpl) getTLSCAClient() (*grpc.ClientConn, membersrvc.TLSCAPClient, error) {
	node.Debug("Getting TLSCA client...")

	// Get Client Connect Node
	conn, err := node.getClientConn(node.conf.getTLSCAPAddr(), node.conf.getTLSCAServerName())
	if err != nil {
		node.Errorf("Failed getting client connection: [%s]", err)
	}

	// TLS CAP Client 생성
	client := membersrvc.NewTLSCAPClient(conn)

	node.Debug("Getting TLSCA client...done")

	return conn, client, nil
}

func (node *nodeImpl) callTLSCACreateCertificate(ctx context.Context, in *membersrvc.TLSCertCreateReq, opts ...grpc.CallOption) (*membersrvc.TLSCertCreateResp, error) {
	conn, tlscaP, err := node.getTLSCAClient()
	if err != nil {
		node.Errorf("Failed dialing in: %s", err)

		return nil, err
	}
	defer conn.Close()

	resp, err := tlscaP.CreateCertificate(ctx, in, opts...)
	if err != nil {
		node.Errorf("Failed requesting tls certificate: %s", err)

		return nil, err
	}

	return resp, nil
}
