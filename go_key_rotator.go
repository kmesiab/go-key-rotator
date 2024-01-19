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
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"
)

// Not exported
const (
	awsStringSecureString = "SecureString"
)

// Exported constants
const (
	DefaultKeySize = MaxKeySize
	MinKeySize     = 2048
	MaxKeySize     = 4096
	RSATypePrivate = "RSA PRIVATE KEY"
	RSATypePublic  = "RSA PUBLIC KEY"
)

type KeyRotator struct {
	ParamStore ParameterStoreInterface
}

// NewKeyRotator creates a new instance of KeyRotator with the given ParameterStore.
func NewKeyRotator(ps ParameterStoreInterface) *KeyRotator {
	return &KeyRotator{ParamStore: ps}
}

// GetCurrentRSAPrivateKey retrieves the current RSA private key used for signing.
// This function fetches the private key from AWS Parameter Store, where it is stored
// in PEM format. The function then decodes the PEM encoded data to obtain the RSA private key
// and returns it for use in cryptographic operations like token signing.
// Returns an error if it fails to retrieve or decode the private key.
func (r *KeyRotator) GetCurrentRSAPrivateKey(parameterStoreKey string) (*rsa.PrivateKey, error) {
	// Retrieve the private key string from Parameter Store
	privateKeyPEM, err := r.ParamStore.GetParameter(parameterStoreKey)

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
func (r *KeyRotator) GetCurrentRSAPublicKey(parameterStoreKey string) (*rsa.PublicKey, error) {
	publicKeyPEM, err := r.ParamStore.GetParameter(parameterStoreKey)
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

// GenerateKeyPair creates a new RSA public/private key pair of the specified size.
// It is a convenience function for quickly generating RSA keys for cryptographic operations.
// The size parameter specifies the length of the key in bits and must be at least 1024 bits
// to ensure a minimum level of security. The function returns a pointer to the generated RSA
// public key, a pointer to the RSA private key, and an error. An error is returned if the key
// size is less than the minimum requirement or if there is an issue in key generation.
//
// Parameters:
// - size: The size of the RSA key pair to generate, in bits. Must be at least 1024 bits.
//
// Returns:
// - *rsa.PublicKey: A pointer to the generated RSA public key.
// - *rsa.PrivateKey: A pointer to the generated RSA private key.
// - error: An error object, which is non-nil if there is an issue in key generation.
//
// Usage:
// Use this function to quickly generate RSA key pairs for encryption, decryption, signing,
// or other cryptographic operations, where a specific key size is required.
func (r *KeyRotator) GenerateKeyPair(size int) (*rsa.PublicKey, *rsa.PrivateKey, error) {
	if size < MinKeySize || size > MaxKeySize {

		return nil, nil, fmt.Errorf(
			"key size must be between %d and %d bits", MinKeySize, MaxKeySize,
		)
	}

	privateKey, err := generateRSAPrivateKey(size)

	if err != nil {

		return nil, nil, err
	}

	return &privateKey.PublicKey, privateKey, nil
}

// Rotate generates and stores new RSA private and public keys in
// AWS Parameter Store with a specified key size.
//
// This function allows specifying the size of the RSA key pair to be
// generated, providing flexibility in terms of security and performance.
//
// The steps involved in this function are:
// 1. Generate a new RSA key pair with the provided key size.
// 2. Encode the private key into PEM format.
// 3. Extract and encode the public key from the private key into PEM format.
// 4. Store both keys in AWS Parameter Store as SecureStrings.
//
// Parameters:
// - parameterStoreKeyNamePrivateKey: The identifier for storing the private key.
// - parameterStoreKeyNamePublicKey: The identifier for storing the public key.
// - keySize: The size of the RSA key pair to generate, in bits.
// - session: The AWS session for accessing Parameter Store.
//
// Returns:
// - *rsa.PrivateKey: The generated RSA private key.
// - *rsa.PublicKey: The corresponding RSA public key.
// - error: Non-nil if there is an issue in key generation, encoding, or storing.
//
// Usage:
// This function is used when specific control over the key size is required during
// key rotation, suitable for scenarios where custom key sizes are needed.
func (r *KeyRotator) Rotate(
	parameterStoreKeyNamePrivateKey,
	parameterStoreKeyNamePublicKey string,
	keySize int,
) (*rsa.PrivateKey, *rsa.PublicKey, error) {

	if parameterStoreKeyNamePrivateKey == "" || parameterStoreKeyNamePublicKey == "" {

		return nil, nil, errors.New("invalid parameter names: names cannot be empty")
	}

	publicKey, privateKey, err := r.GenerateKeyPair(keySize)

	if err != nil {

		return nil, nil, err
	}

	privateKeyPEM := EncodePrivateKeyToPEM(privateKey)
	publicKeyPEM, err := EncodePublicKeyToPEM(publicKey)

	if err != nil {

		return nil, nil, err
	}

	// Store private key
	err = r.ParamStore.PutParameter(
		parameterStoreKeyNamePrivateKey,
		string(privateKeyPEM),
		awsStringSecureString,
	)

	if err != nil {

		return nil, nil, err
	}

	// Store public key
	err = r.ParamStore.PutParameter(
		parameterStoreKeyNamePublicKey,
		string(publicKeyPEM),
		awsStringSecureString,
	)

	if err != nil {

		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

// RotatePrivateKeyAndPublicKey [DEPRECATED] generates and stores new RSA
// private and public keys in AWS Parameter Store using a default key size.
//
// This function is a convenience wrapper around the Rotate function,
// using a predefined default key size (DefaultKeySize).
// It performs the same steps as Rotate but without the need to specify
// the key size. The steps are:
//
// 1. Generate a new RSA key pair with the default key size (DefaultKeySize).
// 2. Encode the private key into PEM format.
// 3. Extract and encode the public key from the private key into PEM format.
// 4. Store both keys in AWS Parameter Store as SecureStrings.
//
// Parameters:
// - parameterStoreKeyNamePrivateKey: The identifier for storing the private key.
// - parameterStoreKeyNamePublicKey: The identifier for storing the public key.
// - session: (UNUSED) The AWS session for accessing Parameter Store.
//
// Returns:
// - *rsa.PrivateKey: The generated RSA private key.
// - *rsa.PublicKey: The corresponding RSA public key.
// - error: Non-nil if there is an issue in key generation, encoding, or storing.
//
// Usage:
// This function is intended for standard key rotation scenarios where the
// default key size is sufficient.
func (r *KeyRotator) RotatePrivateKeyAndPublicKey(
	parameterStoreKeyNamePrivateKey string,
	parameterStoreKeyNamePublicKey string,
	_ *session.Session,
) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	return r.Rotate(
		parameterStoreKeyNamePrivateKey,
		parameterStoreKeyNamePublicKey,
		DefaultKeySize,
	)
}

// EncodePrivateKeyToPEM converts an RSA private key into PEM (Privacy Enhanced Mail) format.
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
// Function to encode an RSA private key to PEM format
func EncodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	if privateKey == nil {

		return nil
	}

	privateKeyPEM := &pem.Block{
		Type:  RSATypePrivate,
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	return pem.EncodeToMemory(privateKeyPEM)
}

// EncodePublicKeyToPEM to encode an RSA public key to PEM format
func EncodePublicKeyToPEM(publicKey *rsa.PublicKey) ([]byte, error) {

	if publicKey == nil {

		return nil, errors.New("public key is nil")
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)

	if err != nil {

		return nil, err
	}

	publicKeyPEM := &pem.Block{
		Type:  RSATypePublic,
		Bytes: publicKeyBytes,
	}

	return pem.EncodeToMemory(publicKeyPEM), nil
}

// generateRSAPrivateKey creates a new RSA private key of a specified size.
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
func generateRSAPrivateKey(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}
