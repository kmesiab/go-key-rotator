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
	RSATypePrivate                  = "RSA PRIVATE KEY"
	RSATypePublic                   = "RSA PUBLIC KEY"
	parameterStoreKeyNamePrivateKey = "private_rsa_key"
	parameterStoreKeyNamePublicKey  = "public_rsa_key"
)

// GetCurrentRSAPrivateKey retrieves the current RSA private key used for signing.
// This function fetches the private key from AWS Parameter Store, where it is stored
// in PEM format. The function then decodes the PEM encoded data to obtain the RSA private key
// and returns it for use in cryptographic operations like token signing.
// Returns an error if it fails to retrieve or decode the private key.
func GetCurrentRSAPrivateKey() (*rsa.PrivateKey, error) {
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

// GetCurrentRSAPublicKey retrieves the current RSA public key used for operations like verifying signatures.
// It fetches the public key from AWS Parameter Store, where it's stored in PEM (Privacy Enhanced Mail) format.
//
// The function performs the following steps:
//  1. Fetch the PEM-encoded public key string from the AWS Parameter Store using the key name defined in
//     parameterStoreKeyNamePublicKey.
//  2. Decode the PEM encoded data to extract the RSA public key.
//     - PEM is a Base64 encoded format with delimiters for storing cryptographic keys and is widely used for its readability.
//  3. Parse the decoded PEM block to get the actual RSA public key.
//     - This uses x509.ParsePKIXPublicKey for parsing the public key in PKIX format.
//  4. Validate and assert the type of the parsed key to ensure it is an RSA public key.
//
// Returns:
//   - *rsa.PublicKey: The RSA public key retrieved and decoded from the Parameter Store.
//   - error: An error object if any issue occurs during the key retrieval and decoding process. Possible errors include
//     failure to fetch from Parameter Store, failure to decode the PEM block, or the data not being an RSA public key.
//
// Usage:
// This function is typically used for cryptographic operations that require an RSA public key, such as verifying JWT tokens.
func GetCurrentRSAPublicKey() (*rsa.PublicKey, error) {
	publicKeyPEM, err := getParameterStoreValue(parameterStoreKeyNamePublicKey)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing the public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("not an RSA public key")
	}
}

// RotatePrivateKeyAndPublicKey generates and stores new RSA private and public keys in AWS Parameter Store.
//
// This function performs the following steps:
// 1. Generate a new RSA key pair with a specified key size (2048 bits in this case).
//   - The 2048-bit size is chosen for a balance between strong security and acceptable performance.
//
// 2. Encode the generated private key into PEM format.
//   - The PEM (Privacy Enhanced Mail) format is widely used for storing cryptographic keys as it
//     is readable and supports encryption for private keys.
//
// 3. Extract and encode the public key from the generated private key into PEM format.
// 4. Store both the private and public keys in AWS Parameter Store.
//   - The keys are stored as SecureStrings, meaning they are encrypted in the store.
//   - The private key is stored using the key identifier 'parameterStoreKeyNamePrivateKey'.
//   - The public key is stored using the key identifier 'parameterStoreKeyNamePublicKey'.
//
// Returns:
// - *rsa.PrivateKey: A pointer to the newly generated RSA private key.
// - *rsa.PublicKey: A pointer to the corresponding RSA public key.
// - error: An error object which is non-nil if there was an issue in key generation, encoding, or storing.
//
// Errors can occur in the following situations:
// - Failure to generate the RSA key pair.
// - Failure to encode the keys in PEM format.
// - Failure to store the keys in AWS Parameter Store.
//
// Usage:
// This function is intended to be used for rotating RSA keys periodically to maintain security.
// Rotating keys helps in minimizing the risk if a key gets compromised and is an essential practice
// in cryptographic key lifecycle management.
func RotatePrivateKeyAndPublicKey() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := generateRSAKeyPair(2048)
	if err != nil {
		return nil, nil, err
	}

	privateKeyPEM := encodePrivateKeyToPEM(privateKey)
	publicKeyPEM, err := encodePublicKeyToPEM(&privateKey.PublicKey)

	if err != nil {
		return nil, nil, err
	}

	// Store private key
	err = SetParameterStoreValue(parameterStoreKeyNamePrivateKey, privateKeyPEM, AWSStringSecureString)

	if err != nil {
		return nil, nil, err
	}

	// Store public key
	err = SetParameterStoreValue(parameterStoreKeyNamePublicKey, publicKeyPEM, AWSStringSecureString)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, &privateKey.PublicKey, nil
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
		Type:  RSATypePrivate,
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	return string(privateKeyPEM)
}

func encodePublicKeyToPEM(publicKey *rsa.PublicKey) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)

	if err != nil {
		return "", err
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  RSATypePublic,
		Bytes: publicKeyBytes,
	})
	return string(publicKeyPEM), nil
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
