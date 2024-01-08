package main

import (
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"

	rotator "github.com/kmesiab/go-key-rotator"
)

const (
	psPrivateKeyName = "private_rsa_key"
	psPublicKeyName  = "public_rsa_key"

	privateKeyFileName = "private.pem"
	publicKeyFileName  = "public.pem"
)

func main() {

	var (
		err              error
		sess             *session.Session
		privateKey       *rsa.PrivateKey
		publicKey        *rsa.PublicKey
		encodedPublicKey []byte
	)

	config := aws.NewConfig().WithRegion("us-west-2")

	if sess, err = session.NewSession(config); err != nil {
		fmt.Printf("Error creating AWS config: %s\n", err)

		return
	}

	privateKey, publicKey, err = rotator.RotatePrivateKeyAndPublicKey(
		psPrivateKeyName, psPublicKeyName, sess,
	)

	if err != nil {
		fmt.Printf("Error rotating keys: %s\n", err)

		return
	}

	if err := writePEMToFile(privateKeyFileName, rotator.EncodePrivateKeyToPEM(privateKey)); err != nil {
		fmt.Printf("Error writing private key to file: %s\n", err)

		return
	}

	if encodedPublicKey, err = rotator.EncodePublicKeyToPEM(publicKey); err != nil {
		fmt.Printf("Error encoding public key: %s\n", err)

		return
	}

	if err = writePEMToFile(publicKeyFileName, encodedPublicKey); err != nil {
		fmt.Printf("Error writing public key to file: %s\n", err)

		return
	}

	fmt.Println("Keys successfully rotated and saved.")
}

// Function to write PEM data to a file
func writePEMToFile(fileName string, pemData []byte) error {
	return os.WriteFile(fileName, pemData, 0644)
}
