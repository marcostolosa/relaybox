package cert

import (
	"bytes"
	"crypto/tls"
	"os"

	"golang.org/x/crypto/pkcs12"
)

// LoadPFX loads a PFX/PKCS#12 bundle returning a tls.Certificate.
func LoadPFX(pfxPath, password string) (*tls.Certificate, error) {
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		return nil, err
	}

	privateKey, leaf, err := pkcs12.Decode(pfxData, password)
	if err != nil {
		return nil, err
	}

	certChain := [][]byte{leaf.Raw}

	blocks, err := pkcs12.ToPEM(pfxData, password)
	if err != nil {
		return nil, err
	}

	for _, block := range blocks {
		if block.Type != "CERTIFICATE" {
			continue
		}
		if bytes.Equal(block.Bytes, leaf.Raw) {
			continue
		}
		certChain = append(certChain, block.Bytes)
	}

	return &tls.Certificate{
		Certificate: certChain,
		PrivateKey:  privateKey,
		Leaf:        leaf,
	}, nil
}
