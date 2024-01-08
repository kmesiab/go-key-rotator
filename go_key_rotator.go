// Package go_key_rotator provides a comprehensive solution for RSA key management in Go applications.
// It facilitates the generation, rotation, and storage of RSA private keys, ensuring secure handling
// and integration with AWS Parameter Store for encrypted storage. The package includes functionalities
// to generate new RSA keys, encode them in PEM format, and manage their lifecycle by securely storing
// and retrieving them from AWS Parameter Store. This aids in enhancing cryptographic practices, allowing
// for secure token generation and verification. The package is designed to be robust and easy to integrate
// into Go applications requiring high standards of security for key management and encryption.
package go_key_rotator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
)

const (
	AWSStringSecureString           = "SecureString"
	RSAType                         = "RSA PRIVATE KEY"
	parameterStoreKeyNamePrivateKey = "private_rsa_key"
)

// GetCurrentRSAKey retrieves the current RSA private key used for signing.
// This function fetches the private key from AWS Parameter Store, where it is stored
// in PEM format. The function then decodes the PEM encoded data to obtain the RSA private key
// and returns it for use in cryptographic operations like token signing.
// Returns an error if it fails to retrieve or decode the private key.
func GetCurrentRSAKey() (*rsa.PrivateKey, error) {
	// Retrieve the private key string from Parameter Store
	privateKeyPEM, err := getParameterStoreValue(parameterStoreKeyNamePrivateKey)
	if err != nil {
		return nil, err
	}

	// Decode the PEM encoded data
	// PEM (Privacy-Enhanced Mail) format is used to store cryptographic keys and certificates.
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		// Return an error if the PEM data could not be decoded
		// This typically means the data is not in valid PEM format
		return nil, errors.New("failed to decode PEM block containing the key")
	}

	// Parse the block to get an RSA private key
	// 'x509.ParsePKCS1PrivateKey' is used to parse PKCS#1 RSA private key format
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// RotatePrivateKey generates a new RSA private key and stores it in AWS Parameter Store.
// This function is used to rotate the RSA private key periodically, enhancing the security
// of the system by replacing old keys with new ones.
// The function generates a new 2048-bit RSA key pair, encodes it in PEM format, and then
// updates the stored key value in the AWS Parameter Store.
// Returns the newly generated RSA private key or an error if any step in the process fails.
func RotatePrivateKey() (*rsa.PrivateKey, error) {
	// Generate a new 2048-bit RSA key pair
	// 2048 bits is a commonly used key size that provides a good balance between security and performance
	key, err := generateRSAKeyPair(2048)

	if err != nil {
		return nil, err
	}

	// Encode the private key into PEM format
	// PEM (Privacy-Enhanced Mail) format is a base64-encoded format used to represent
	// cryptographic keys and certificates. The 'encodePrivateKeyToPEM' function handles this encoding
	privateKeyPEM := encodePrivateKeyToPEM(key)

	// Store the new key in AWS Parameter Store
	// The key is stored as a SecureString, which means it will be encrypted in the Parameter Store
	// 'parameterStoreKeyNamePrivateKey' is a constant that identifies the Parameter Store key where
	// the RSA key is stored
	err = SetParameterStoreValue(parameterStoreKeyNamePrivateKey, privateKeyPEM, AWSStringSecureString)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// generateRSAKeyPair creates a new RSA private key of a specified size.
// This function is used to generate RSA keys for cryptographic operations,
// such as token signing. RSA keys are used in asymmetric cryptography,
// where a private key is used for signing or decryption and a public key
// for verification or encryption.
//
// Parameters:
//
//	bits - The size of the RSA key in bits. Common sizes are 2048 or 4096 bits,
//	       but the required size can vary based on security requirements.
//
// Returns:
//
//	A pointer to the generated rsa.PrivateKey or an error if the key generation fails.
//
// The function uses 'crypto/rand' Reader as a source of cryptographically secure random data
// to ensure the security of the generated key. The 'bits' parameter defines the strength of the key:
// larger values provide more security but also result in slower cryptographic operations.
func generateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// encodePrivateKeyToPEM converts an RSA private key into PEM (Privacy Enhanced Mail) format.
// PEM format is a widely used encoding format for cryptographic keys and certificates,
// which is essentially Base64 encoded data with additional header and footer lines.
//
// Parameters:
//
//	privateKey - A pointer to the rsa.PrivateKey that needs to be encoded.
//
// Returns:
//
//	A string representing the RSA private key in PEM format.
//
// The function uses the 'pem' package from the Go standard library to perform the encoding.
// It takes the RSA private key, converts it into a byte slice in PKCS#1 format using 'x509.MarshalPKCS1PrivateKey',
// and then creates a PEM block with this byte slice. The 'Type' field of the PEM block is set to the value of 'RSAType',
// typically "RSA PRIVATE KEY", indicating the type of key encoded in the PEM block.
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) string {
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  RSAType,
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	return string(privateKeyPEM)
}

// getParameterStoreValue retrieves a value from AWS Parameter Store.
// Parameters:
//
//	name - The name of the parameter to retrieve. This is the key used when the parameter
//	       was stored in the Parameter Store.
//
// Returns:
//
//	The value of the parameter as a string and an error. If the retrieval is successful,
//	the error will be nil. If the retrieval fails, the returned string will be empty,
//	and the error will contain details about the failure.
//
// This function is used to fetch configuration data or secrets (like private keys) from
// the AWS Parameter Store, which is a service that provides secure, hierarchical storage
// for configuration data management and secrets management. The function creates a new AWS
// session and uses the SSM (Simple Systems Manager) service client to retrieve the parameter.
// If the parameter is a SecureString, it will be automatically decrypted by the service
// (as indicated by 'WithDecryption' set to true) before being returned.
func getParameterStoreValue(name string) (string, error) {

	var (
		err   error
		sess  *session.Session
		param *ssm.GetParameterOutput
	)

	if sess, err = session.NewSession(); err != nil {
		return "", err
	}

	svc := ssm.New(sess)
	input := &ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(true),
	}

	if param, err = svc.GetParameter(input); err != nil {
		return "", err
	}

	return *param.Parameter.Value, nil
}

// SetParameterStoreValue stores a given value in the AWS Parameter Store.
//
// Parameters:
//
//	parameterName - The name of the parameter to set in the Parameter Store.
//	                 This name is used as the key to retrieve the parameter later.
//	value - The value to be stored. In the context of RSA keys, this
//	                 would typically be the private key in PEM format.
//	parameterType - The type of the parameter, usually "String" or "SecureString".
//	                 "SecureString" is used for sensitive data that needs to be encrypted.
//
// Returns:
//
//	An error if the storage operation fails, otherwise nil.
//
// This function initializes an AWS session and uses the SSM (Simple Systems Manager)
// service client to store a parameter in the Parameter Store. The parameter can be
// a regular string or an encrypted string (SecureString) based on the 'parameterType'.
// The 'Overwrite' field in the PutParameterInput struct is set to true, allowing this
// function to update the value of an existing parameter with the same name.
func SetParameterStoreValue(parameterName, value, parameterType string) error {
	var (
		err  error
		sess *session.Session
	)

	if sess, err = session.NewSession(); err != nil {
		return err
	}

	svc := ssm.New(sess)
	input := &ssm.PutParameterInput{
		Name:      aws.String(parameterName),
		Value:     aws.String(value),
		Type:      aws.String(parameterType),
		Overwrite: aws.Bool(true),
	}

	_, err = svc.PutParameter(input)

	return err
}
