package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"homegate.local/homegate/internal/certstore"
)

func loadCertificateKey(path string) (*ecdsa.PrivateKey, []byte, bool, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(b)
		if block != nil {
			if k, parseErr := x509.ParseECPrivateKey(block.Bytes); parseErr == nil {
				return k, b, false, nil
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, nil, false, fmt.Errorf("read certificate private key: %w", err)
	}

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, false, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, nil, false, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return k, keyPEM, true, nil
}

func certExpiryPEM(b []byte) (time.Time, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return time.Time{}, fmt.Errorf("certificate PEM is invalid")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

func publishCertificatePair(certPath, keyPath string, chain, keyPEM []byte, publishKey bool, expectedDomains []string) (time.Time, error) {
	if _, err := tls.X509KeyPair(chain, keyPEM); err != nil {
		return time.Time{}, fmt.Errorf("issued certificate/private key mismatch: %w", err)
	}
	if err := certstore.ValidatePEMIdentities(chain, expectedDomains); err != nil {
		return time.Time{}, fmt.Errorf("issued certificate identity mismatch: %w", err)
	}
	exp, err := certExpiryPEM(chain)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse issued certificate: %w", err)
	}

	if !publishKey {
		if err := atomicWrite(certPath, chain, 0600); err != nil {
			return time.Time{}, err
		}
		return exp, nil
	}

	oldKey, oldKeyErr := os.ReadFile(keyPath)
	hadOldKey := oldKeyErr == nil
	if oldKeyErr != nil && !os.IsNotExist(oldKeyErr) {
		return time.Time{}, fmt.Errorf("read previous certificate private key: %w", oldKeyErr)
	}
	if err := atomicWrite(keyPath, keyPEM, 0600); err != nil {
		return time.Time{}, err
	}
	if err := atomicWrite(certPath, chain, 0600); err != nil {
		var rollbackErr error
		if hadOldKey {
			rollbackErr = atomicWrite(keyPath, oldKey, 0600)
		} else {
			rollbackErr = os.Remove(keyPath)
			if os.IsNotExist(rollbackErr) {
				rollbackErr = nil
			}
		}
		if rollbackErr != nil {
			return time.Time{}, fmt.Errorf("publish certificate: %v; restore previous private key: %w", err, rollbackErr)
		}
		return time.Time{}, err
	}
	return exp, nil
}
