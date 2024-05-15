package keypair

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

// CertificateLoader handles loading and parsing X.509 certificates.
type KeyPair struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

func InitKeypair(certFilePath string, keyFilePath string) (*KeyPair, error) {
	keyPair := &KeyPair{}
	err := keyPair.loadKey(keyFilePath)
	if err != nil {
		log.Fatalf("failed to load private key: %v", err)
		return nil, err
	}
	err = keyPair.loadCert(certFilePath)
	if err != nil {
		log.Fatalf("failed to load certificate: %v", err)
		return nil, err
	}

	return keyPair, nil
}

func (kp *KeyPair) loadKey(filePath string) error {
	keyPEM, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %v", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block from key file")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}
	var ok bool
	kp.Key, ok = key.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("parsed private key is not an RSA private key")
	}
	return nil
}

func (kp *KeyPair) loadCert(filePath string) error {
	certFile, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %v", err)
	}
	certBlock, _ := pem.Decode(certFile)
	if certBlock == nil {
		return fmt.Errorf("failed to decode PEM block from certificate file")
	}
	kp.Cert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}
	return nil
}

func (kp *KeyPair) SignCSR(csrPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %v", err)
	}

	ski := sha1.Sum(csr.RawSubjectPublicKeyInfo)
	// Create a template for the certificate
	template := x509.Certificate{
		SerialNumber:   generateRandomSerial(),
		Subject:        csr.Subject,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(10 * 365 * 24 * time.Hour), // 1 year validity
		AuthorityKeyId: kp.Cert.AuthorityKeyId,
		SubjectKeyId:   ski[:],
		// ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Issuer: kp.Cert.Subject,
	}

	// Sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, kp.Cert, csr.PublicKey, kp.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Encode the certificate to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return certPEM, nil
}

func generateRandomSerial() *big.Int {
	// Generate a random 128-bit number (16 bytes)
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)

	// if rand.Read fails, generate from timestamp
	if err != nil {
		return new(big.Int).SetInt64(time.Now().UnixMilli())
	}
	// Convert the random bytes to a big.Int
	return new(big.Int).SetBytes(randomBytes)
}
