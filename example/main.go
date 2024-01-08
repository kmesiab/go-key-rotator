package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	rotator "github.com/kmesiab/go-key-rotator"
)

const (
	privateKeyFileName = "private.pem"
	publicKeyFileName  = "public.pem"
)

func main() {
	privateKey, publicKey, err := rotator.RotatePrivateKeyAndPublicKey()
	if err != nil {
		fmt.Printf("Error rotating keys: %s\n", err)
		return
	}

	if err := writePEMToFile(privateKeyFileName, encodePrivateKeyToPEM(privateKey)); err != nil {
		fmt.Printf("Error writing private key to file: %s\n", err)
		return
	}

	if err := writePEMToFile(publicKeyFileName, encodePublicKeyToPEM(publicKey)); err != nil {
		fmt.Printf("Error writing public key to file: %s\n", err)
		return
	}

	fmt.Println("Keys successfully rotated and saved.")
}

// Function to encode an RSA private key to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	privateKeyPEM := &pem.Block{
		Type:  rotator.RSATypePrivate,
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	return pem.EncodeToMemory(privateKeyPEM)
}

// Function to encode an RSA public key to PEM format
func encodePublicKeyToPEM(publicKey *rsa.PublicKey) []byte {
	publicKeyBytes, _ := x509.MarshalPKIXPublicKey(publicKey) // Error handling is omitted here
	publicKeyPEM := &pem.Block{
		Type:  rotator.RSATypePublic,
		Bytes: publicKeyBytes,
	}
	return pem.EncodeToMemory(publicKeyPEM)
}

// Function to write PEM data to a file
func writePEMToFile(fileName string, pemData []byte) error {
	return os.WriteFile(fileName, pemData, 0644)
}
