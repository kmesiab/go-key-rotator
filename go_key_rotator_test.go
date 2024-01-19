package go_key_rotator_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rotator "github.com/kmesiab/go-key-rotator"
)

func TestGetCurrentRSAPublicKey_Success(t *testing.T) {
	const testKeyName = "test-valid-public-key"
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	// Generate a new RSA key pair
	publicKey, _, err := testRotator.GenerateKeyPair(rotator.DefaultKeySize)
	require.NoError(t, err, "Failed to generate RSA key pair")

	// Encode the public key to PEM
	publicKeyPEM, err := rotator.EncodePublicKeyToPEM(publicKey)
	require.NoError(t, err, "Failed to encode RSA public key to PEM")

	// Store the encoded public key in the mock parameter store
	err = testRotator.ParamStore.PutParameter(testKeyName, string(publicKeyPEM), "SecureString")
	require.NoError(t, err, "Failed to store public key in mock parameter store")

	// Retrieve the public key using the KeyRotator
	retrievedPublicKey, err := testRotator.GetCurrentRSAPublicKey(testKeyName)
	require.NoError(t, err, "Failed to retrieve public key")

	// Assert that the retrieved public key matches the original public key
	assert.Equal(t, publicKey.N, retrievedPublicKey.N, "Public key modulus does not match")
	assert.Equal(t, publicKey.E, retrievedPublicKey.E, "Public key exponent does not match")
}

func TestGetCurrentRSAPublicKey_EmptyPEMData(t *testing.T) {
	const testKeyName = "test-empty-pem"
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	// Store an empty PEM block in the mock parameter store
	emptyPEM := `-----BEGIN RSA PUBLIC KEY-----
-----END RSA PUBLIC KEY-----`
	err := testRotator.ParamStore.PutParameter(testKeyName, emptyPEM, "SecureString")
	assert.NoError(t, err, "Failed to store empty PEM data in mock parameter store")

	// Attempt to retrieve and parse the empty PEM data
	_, err = testRotator.GetCurrentRSAPublicKey(testKeyName)

	// Assert that an error is returned due to empty PEM data
	assert.Error(t, err, "Expected an error due to empty PEM data")
}

func TestGetCurrentRSAPublicKey_ParsingError(t *testing.T) {
	const testKeyName = "test-parsing-error"
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	// Store a valid PEM block with content that causes parsing to fail
	parsingErrorPEM := `-----BEGIN RSA PUBLIC KEY-----
InvalidPublicKeyData
-----END RSA PUBLIC KEY-----`
	err := testRotator.ParamStore.PutParameter(testKeyName, parsingErrorPEM, "SecureString")
	assert.NoError(t, err, "Failed to store PEM data that causes parsing error in mock parameter store")

	// Attempt to retrieve and parse the PEM data that causes parsing error
	_, err = testRotator.GetCurrentRSAPublicKey(testKeyName)

	// Assert that an error is returned due to parsing error
	assert.Error(t, err, "Expected an error due to public key parsing error")
}

func TestGetCurrentRSAPublicKey_Decoding(t *testing.T) {
	const testKeyName = "test-public-key-invalid"
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	// Store invalid PEM data in the mock parameter store
	invalidPEM := "invalid PEM data"
	err := testRotator.ParamStore.PutParameter(testKeyName, invalidPEM, "SecureString")
	assert.NoError(t, err, "Failed to store invalid public key in mock parameter store")

	// Attempt to retrieve and parse the invalid public key
	_, err = testRotator.GetCurrentRSAPublicKey(testKeyName)

	// Assert that an error is returned due to invalid PEM data
	assert.Error(t, err, "Expected an error due to invalid PEM data")
}

func TestGetCurrentRSAPublicKey(t *testing.T) {
	const testKeyName = "test-public-key"
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	// Generate a new RSA key pair
	publicKey, _, err := testRotator.GenerateKeyPair(rotator.DefaultKeySize)
	assert.NoError(t, err, "Failed to generate RSA key pair")

	// Encode the public key to PEM
	publicKeyPEM, err := rotator.EncodePublicKeyToPEM(publicKey)
	require.NoError(t, err, "Failed to encode RSA public key to PEM")

	// Store the encoded public key in the mock parameter store
	err = testRotator.ParamStore.PutParameter(
		testKeyName,
		string(publicKeyPEM),
		"SecureString",
	)

	assert.NoError(t, err, "Failed to store public key in mock parameter store")

	// Retrieve the public key using the KeyRotator
	retrievedPublicKey, err := testRotator.GetCurrentRSAPublicKey(testKeyName)
	assert.NoError(t, err, "Failed to retrieve public key")
	assert.NotNil(t, retrievedPublicKey, "Retrieved public key is nil")

	// Assert that the retrieved public key matches the original public key
	assert.Equal(t, publicKey.N, retrievedPublicKey.N, "Public key modulus does not match")
	assert.Equal(t, publicKey.E, retrievedPublicKey.E, "Public key exponent does not match")
}

func TestGetCurrentRSAPublicKey_KeyNotFound(t *testing.T) {
	const testKeyName = "test-key-not-found"
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	// Simulate a scenario where the key does not exist in the parameter store
	// In this case, we don't put any key into the mock parameter store

	// Attempt to retrieve a key that does not exist
	_, err := testRotator.GetCurrentRSAPublicKey(testKeyName)

	// Assert that an error is returned due to the key not being found
	assert.Error(t, err, "Expected an error due to the key not being found in the parameter store")
}

func TestGetCurrentRSAPublicKey_NonRSAPublicKey(t *testing.T) {
	const testKeyName = "test-non-rsa-key"
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	// Store a PEM-encoded string that represents a non-RSA key (e.g., an ECDSA key) in the mock parameter store
	nonRSAKeyPEM := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIH84O6hf145Awun9lH6GbesjSmwJ5w1ODxz2ndnTwy5LoAoGCCqGSM49
AwEHoUQDQgAEb5ERgUCa+V0h4I9Fol2j8mFORXnIRW4rZpC+r5C7zjoOALCv34MV
gklEZVFqSEX4FEZ1EeWmwhK8R0fQ7akPRg==
-----END EC PRIVATE KEY-----`
	err := testRotator.ParamStore.PutParameter(testKeyName, nonRSAKeyPEM, "SecureString")
	assert.NoError(t, err, "Failed to store non-RSA key in mock parameter store")

	// Attempt to retrieve and parse the non-RSA key
	_, err = testRotator.GetCurrentRSAPublicKey(testKeyName)

	// Assert that an error is returned due to the key not being an RSA public key
	assert.Error(t, err, "Expected an error due to the key not being an RSA public key")
}

func TestGetCurrentRSAPublicKey_CorruptedPEMData(t *testing.T) {
	const testKeyName = "test-corrupted-pem"
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	// Store a structurally valid but corrupted PEM data in the mock parameter store
	corruptedPEM := `-----BEGIN RSA PUBLIC KEY-----
corrupteddata
-----END RSA PUBLIC KEY-----`
	err := testRotator.ParamStore.PutParameter(testKeyName, corruptedPEM, "SecureString")
	assert.NoError(t, err, "Failed to store corrupted PEM data in mock parameter store")

	// Attempt to retrieve and parse the corrupted PEM data
	_, err = testRotator.GetCurrentRSAPublicKey(testKeyName)

	// Assert that an error is returned due to corrupted PEM data
	assert.Error(t, err, "Expected an error due to corrupted PEM data")
}

func TestGetCurrentRSAPublicKey_IncorrectPEMBlockType(t *testing.T) {
	const testKeyName = "test-incorrect-pem-type"
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	// Store a PEM block with an incorrect type (e.g., "CERTIFICATE") in the mock parameter store
	incorrectPEM := `-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzD8mG5gnEibWoA/AgSW
-----END CERTIFICATE-----`
	err := testRotator.ParamStore.PutParameter(testKeyName, incorrectPEM, "SecureString")
	assert.NoError(t, err, "Failed to store PEM data with incorrect block type in mock parameter store")

	// Attempt to retrieve and parse the PEM data with incorrect block type
	_, err = testRotator.GetCurrentRSAPublicKey(testKeyName)

	// Assert that an error is returned due to incorrect PEM block type
	assert.Error(t, err, "Expected an error due to incorrect PEM block type")
}

func TestGenerateKeyPair_ValidSize(t *testing.T) {
	testRotator := rotator.KeyRotator{}

	// Test with a valid key size
	publicKey, privateKey, err := testRotator.GenerateKeyPair(rotator.DefaultKeySize)
	require.NoError(t, err, "Failed to generate RSA key pair with valid size")
	require.NotNil(t, publicKey, "Public key should not be nil")
	require.NotNil(t, privateKey, "Private key should not be nil")

	// Additional assertions to check the key type and size
	require.IsType(t, &rsa.PublicKey{}, publicKey, "Expected publicKey to be of type *rsa.PublicKey")
	require.IsType(t, &rsa.PrivateKey{}, privateKey, "Expected privateKey to be of type *rsa.PrivateKey")
	require.Equal(t, rotator.DefaultKeySize, publicKey.Size()*8, "Public key size does not match the expected size")
}

func TestGenerateKeyPair_InvalidSize(t *testing.T) {
	testRotator := rotator.KeyRotator{}

	// Test with an invalid key size (e.g., less than 1024 bits)
	_, _, err := testRotator.GenerateKeyPair(512) // Example of invalid key size
	require.Error(t, err, "Expected an error due to invalid key size")
}

func TestGenerateKeyPair_MinimumKeySize(t *testing.T) {
	testRotator := rotator.KeyRotator{}

	// Test with minimum key size
	_, _, err := testRotator.GenerateKeyPair(rotator.MinKeySize)
	require.NoError(t, err, "Should not error with minimum key size")
}

func TestGenerateKeyPair_MaximumKeySize(t *testing.T) {
	testRotator := rotator.KeyRotator{}

	// Test with maximum key size
	_, _, err := testRotator.GenerateKeyPair(rotator.MaxKeySize)
	require.NoError(t, err, "Should not error with maximum key size")
}

func TestGenerateKeyPair_BelowMinimumKeySize(t *testing.T) {
	testRotator := rotator.KeyRotator{}

	// Test with key size below minimum
	_, _, err := testRotator.GenerateKeyPair(rotator.MinKeySize - 1)
	require.Error(t, err, "Expected error with key size below minimum")
}

func TestGenerateKeyPair_AboveMaximumKeySize(t *testing.T) {
	testRotator := rotator.KeyRotator{}

	// Test with key size above maximum
	_, _, err := testRotator.GenerateKeyPair(rotator.MaxKeySize + 1)
	require.Error(t, err, "Expected error with key size above maximum")
}

func TestGenerateKeyPair_CustomKeySize3000(t *testing.T) {
	testRotator := rotator.KeyRotator{}

	// Test with a custom key size of 3000 bits
	publicKey, privateKey, err := testRotator.GenerateKeyPair(3000)
	require.NoError(t, err, "Failed to generate RSA key pair with 3000 bits")
	require.NotNil(t, publicKey, "Public key should not be nil")
	require.NotNil(t, privateKey, "Private key should not be nil")

	// Additional assertions to check the key type and approximate size
	require.IsType(t, &rsa.PublicKey{}, publicKey, "Expected publicKey to be of type *rsa.PublicKey")
	require.IsType(t, &rsa.PrivateKey{}, privateKey, "Expected privateKey to be of type *rsa.PrivateKey")
	require.GreaterOrEqual(t, publicKey.Size()*8, 3000, "Public key size should be at least 3000 bits")
}

func TestRotate_Success(t *testing.T) {
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	privateKeyName := "privateKey"
	publicKeyName := "publicKey"

	privateKey, publicKey, err := testRotator.Rotate(privateKeyName, publicKeyName, rotator.DefaultKeySize)
	require.NoError(t, err, "Rotate should succeed with valid key size")
	require.NotNil(t, privateKey, "Private key should not be nil")
	require.NotNil(t, publicKey, "Public key should not be nil")

	// Verify keys are stored in the parameter store
	storedPrivateKey, err := testRotator.ParamStore.GetParameter(privateKeyName)
	require.NoError(t, err, "Failed to retrieve stored private key")
	require.NotEmpty(t, storedPrivateKey, "Stored private key should not be empty")

	storedPublicKey, err := testRotator.ParamStore.GetParameter(publicKeyName)
	require.NoError(t, err, "Failed to retrieve stored public key")
	require.NotEmpty(t, storedPublicKey, "Stored public key should not be empty")
}

func TestRotate_InvalidKeySize(t *testing.T) {
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	_, _, err := testRotator.Rotate("privateKey", "publicKey", 1024) // Invalid key size
	assert.Error(t, err, "Rotate should fail with invalid key size")
}

func TestRotate_BoundaryKeySizes(t *testing.T) {
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	// Test with minimum key size
	_, _, err := testRotator.Rotate("privateKeyMin", "publicKeyMin", rotator.MinKeySize)
	require.NoError(t, err, "Rotate should succeed with minimum key size")

	// Test with maximum key size
	_, _, err = testRotator.Rotate("privateKeyMax", "publicKeyMax", rotator.MaxKeySize)
	require.NoError(t, err, "Rotate should succeed with maximum key size")
}

func TestRotate_ParameterStoreError(t *testing.T) {
	// Enhance MockParameterStore to simulate an error during PutParameter
	mockStore := rotator.NewMockParameterStore(true)

	testRotator := rotator.KeyRotator{
		ParamStore: mockStore,
	}

	// Simulate an error in the parameter store
	mockStore.SimulateError(true)

	// Attempt rotation with a simulated parameter store error
	_, _, err := testRotator.Rotate("privateKey", "publicKey", rotator.DefaultKeySize)
	assert.Error(t, err, "Rotate should fail when parameter store encounters an error")

	// Reset the error simulation for future tests
	mockStore.SimulateError(false)
}

func TestEncodePrivateKeyToPEM(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rotator.DefaultKeySize)
	require.NoError(t, err, "Failed to generate RSA private key")

	encodedPEM := rotator.EncodePrivateKeyToPEM(privateKey)
	require.NotEmpty(t, encodedPEM, "Encoded PEM should not be empty")

	block, _ := pem.Decode(encodedPEM)
	require.NotNil(t, block, "Failed to decode PEM block")
	require.Equal(t, rotator.RSATypePrivate, block.Type, "Incorrect PEM type for private key")
}

func TestEncodePublicKeyToPEM(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rotator.DefaultKeySize)
	require.NoError(t, err, "Failed to generate RSA private key")

	publicKey := &privateKey.PublicKey
	encodedPEM, err := rotator.EncodePublicKeyToPEM(publicKey)
	require.NoError(t, err, "Failed to encode RSA public key to PEM")
	require.NotEmpty(t, encodedPEM, "Encoded PEM should not be empty")

	block, _ := pem.Decode(encodedPEM)
	require.NotNil(t, block, "Failed to decode PEM block")
	require.Equal(t, rotator.RSATypePublic, block.Type, "Incorrect PEM type for public key")
}

func TestEncodePrivateKeyToPEM_SmallKeySize(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rotator.MinKeySize)
	require.NoError(t, err, "Failed to generate RSA private key with small key size")

	encodedPEM := rotator.EncodePrivateKeyToPEM(privateKey)
	require.NotEmpty(t, encodedPEM, "Encoded PEM should not be empty for small key size")
}

func TestEncodePrivateKeyToPEM_NullPrivateKey(t *testing.T) {
	encodedPEM := rotator.EncodePrivateKeyToPEM(nil)
	require.Empty(t, encodedPEM, "Encoded PEM should be empty for nil private key")
}

func TestEncodePublicKeyToPEM_SmallKeySize(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rotator.MinKeySize)
	require.NoError(t, err, "Failed to generate RSA private key with small key size")

	publicKey := &privateKey.PublicKey
	encodedPEM, err := rotator.EncodePublicKeyToPEM(publicKey)
	require.NoError(t, err, "Failed to encode RSA public key to PEM for small key size")
	require.NotEmpty(t, encodedPEM, "Encoded PEM should not be empty for small key size")
}

func TestEncodePublicKeyToPEM_NullPublicKey(t *testing.T) {
	encodedPEM, err := rotator.EncodePublicKeyToPEM(nil)
	require.Error(t, err, "Expected error when encoding nil public key to PEM")
	require.Empty(t, encodedPEM, "Encoded PEM should be empty for nil public key")
}

func TestGetCurrentRSAPrivateKey_Success(t *testing.T) {
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, rotator.DefaultKeySize)
	require.NoError(t, err)

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	const keyName = "test-private-key"
	err = testRotator.ParamStore.PutParameter(keyName, string(privateKeyPEM), "SecureString")
	require.NoError(t, err)

	retrievedKey, err := testRotator.GetCurrentRSAPrivateKey(keyName)
	require.NoError(t, err)
	require.NotNil(t, retrievedKey)

	assert.Equal(t, privateKey.D, retrievedKey.D)
}

func TestGetCurrentRSAPrivateKey_KeyNotFound(t *testing.T) {
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	_, err := testRotator.GetCurrentRSAPrivateKey("non-existent-key")
	assert.Error(t, err, "Expected an error for non-existent key")
}

func TestGetCurrentRSAPrivateKey_InvalidPEMData(t *testing.T) {
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	err := testRotator.ParamStore.PutParameter("invalid-pem-key", "invalid PEM data", "SecureString")
	assert.NoError(t, err)

	_, err = testRotator.GetCurrentRSAPrivateKey("invalid-pem-key")
	assert.Error(t, err, "Expected an error for invalid PEM data")
}

func TestGetCurrentRSAPrivateKey_NonRSAPrivateKey(t *testing.T) {
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	nonRSAKeyPEM := `-----BEGIN EC PRIVATE KEY-----
    (non-RSA key data)
    -----END EC PRIVATE KEY-----`
	err := testRotator.ParamStore.PutParameter("non-rsa-key", nonRSAKeyPEM, "SecureString")
	assert.NoError(t, err)

	_, err = testRotator.GetCurrentRSAPrivateKey("non-rsa-key")
	assert.Error(t, err, "Expected an error for non-RSA private key")
}

func TestGetCurrentRSAPrivateKey_CorruptedPEMData(t *testing.T) {
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	corruptedPEM := `-----BEGIN RSA PRIVATE KEY-----
    corrupteddata
    -----END RSA PRIVATE KEY-----`
	err := testRotator.ParamStore.PutParameter("corrupted-pem-key", corruptedPEM, "SecureString")
	assert.NoError(t, err)

	_, err = testRotator.GetCurrentRSAPrivateKey("corrupted-pem-key")
	assert.Error(t, err, "Expected an error for corrupted PEM data")
}

func TestGetCurrentRSAPrivateKey_SmallerKeySize(t *testing.T) {
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, rotator.MinKeySize)
	require.NoError(t, err)

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	const keyName = "test-smaller-key"
	err = testRotator.ParamStore.PutParameter(keyName, string(privateKeyPEM), "SecureString")
	require.NoError(t, err)

	retrievedKey, err := testRotator.GetCurrentRSAPrivateKey(keyName)
	require.NoError(t, err)
	require.NotNil(t, retrievedKey)

	assert.Equal(t, privateKey.D, retrievedKey.D)
}

func TestGetCurrentRSAPrivateKey_EmptyKeyName(t *testing.T) {
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	_, err := testRotator.GetCurrentRSAPrivateKey("")
	assert.Error(t, err, "Expected an error for empty key name")
}

func TestGetCurrentRSAPrivateKey_IncorrectlyFormattedPEM(t *testing.T) {
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	incorrectPEM := "Incorrectly Formatted PEM Data"
	err := testRotator.ParamStore.PutParameter("incorrect-pem-key", incorrectPEM, "SecureString")
	assert.NoError(t, err)

	_, err = testRotator.GetCurrentRSAPrivateKey("incorrect-pem-key")
	assert.Error(t, err, "Expected an error for incorrectly formatted PEM data")
}

func TestGetCurrentRSAPrivateKey_NonPEMEncodedData(t *testing.T) {
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	nonPEMData := "This is not PEM encoded data"
	err := testRotator.ParamStore.PutParameter("non-pem-data-key", nonPEMData, "SecureString")
	assert.NoError(t, err)

	_, err = testRotator.GetCurrentRSAPrivateKey("non-pem-data-key")
	assert.Error(t, err, "Expected an error for non-PEM encoded data")
}

func TestGetCurrentRSAPrivateKey_PartiallyCorruptedPEM(t *testing.T) {
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	partiallyCorruptedPEM := `-----BEGIN RSA PRIVATE KEY-----
    partiallycorrupteddata
    -----END RSA PRIVATE KEY-----`
	err := testRotator.ParamStore.PutParameter("partially-corrupted-pem-key", partiallyCorruptedPEM, "SecureString")
	assert.NoError(t, err)

	_, err = testRotator.GetCurrentRSAPrivateKey("partially-corrupted-pem-key")
	assert.Error(t, err, "Expected an error for partially corrupted PEM data")
}

func TestRotatePrivateKeyAndPublicKey_Success(t *testing.T) {
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	privateKeyName := "privateKey"
	publicKeyName := "publicKey"

	privateKey, publicKey, err := testRotator.RotatePrivateKeyAndPublicKey(privateKeyName, publicKeyName, nil)
	require.NoError(t, err, "RotatePrivateKeyAndPublicKey should succeed with valid key size")
	require.NotNil(t, privateKey, "Private key should not be nil")
	require.NotNil(t, publicKey, "Public key should not be nil")

	// Verify keys are stored in the parameter store
	storedPrivateKey, err := testRotator.ParamStore.GetParameter(privateKeyName)
	require.NoError(t, err, "Failed to retrieve stored private key")
	require.NotEmpty(t, storedPrivateKey, "Stored private key should not be empty")

	storedPublicKey, err := testRotator.ParamStore.GetParameter(publicKeyName)
	require.NoError(t, err, "Failed to retrieve stored public key")
	require.NotEmpty(t, storedPublicKey, "Stored public key should not be empty")
}

func TestRotatePrivateKeyAndPublicKey_ParameterStoreError(t *testing.T) {
	mockStore := rotator.NewMockParameterStore(true)
	testRotator := rotator.KeyRotator{
		ParamStore: mockStore,
	}

	privateKeyName := "privateKey"
	publicKeyName := "publicKey"

	_, _, err := testRotator.RotatePrivateKeyAndPublicKey(privateKeyName, publicKeyName, nil)
	assert.Error(t, err, "RotatePrivateKeyAndPublicKey should fail when parameter store encounters an error")
}

func TestRotatePrivateKeyAndPublicKey_CustomSession(t *testing.T) {
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	privateKeyName := "privateKey"
	publicKeyName := "publicKey"

	// Pass a non-nil session argument
	customSession := session.Must(session.NewSession())

	privateKey, publicKey, err := testRotator.RotatePrivateKeyAndPublicKey(privateKeyName, publicKeyName, customSession)
	require.NoError(t, err, "RotatePrivateKeyAndPublicKey should succeed with custom session")
	require.NotNil(t, privateKey, "Private key should not be nil")
	require.NotNil(t, publicKey, "Public key should not be nil")
}

func TestRotatePrivateKeyAndPublicKey_InvalidParameterNames(t *testing.T) {
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false), // False indicates no error simulation
	}

	// Test with invalid parameter names (empty strings)
	_, _, err := testRotator.RotatePrivateKeyAndPublicKey("", "", nil)
	assert.Error(t, err, "RotatePrivateKeyAndPublicKey should fail with invalid parameter names")
}

func TestRotatePrivateKeyAndPublicKey_SpecificKeySize(t *testing.T) {
	testRotator := rotator.KeyRotator{
		ParamStore: rotator.NewMockParameterStore(false),
	}

	privateKeyName := "privateKey"
	publicKeyName := "publicKey"

	// Use a specific key size (e.g., DefaultKeySize)
	privateKey, publicKey, err := testRotator.RotatePrivateKeyAndPublicKey(privateKeyName, publicKeyName, nil)
	require.NoError(t, err, "RotatePrivateKeyAndPublicKey should succeed with specific key size")
	require.NotNil(t, privateKey, "Private key should not be nil")
	require.NotNil(t, publicKey, "Public key should not be nil")

	assert.Equal(t, rotator.DefaultKeySize, privateKey.PublicKey.Size()*8, "Key size does not match DefaultKeySize")
}

func TestRotatePrivateKeyAndPublicKey_MockStoreErrorSimulation(t *testing.T) {
	mockStore := rotator.NewMockParameterStore(true) // Simulate errors
	testRotator := rotator.KeyRotator{
		ParamStore: mockStore,
	}

	privateKeyName := "privateKey"
	publicKeyName := "publicKey"

	// Attempt rotation with a simulated parameter store error
	_, _, err := testRotator.RotatePrivateKeyAndPublicKey(privateKeyName, publicKeyName, nil)
	assert.Error(t, err, "RotatePrivateKeyAndPublicKey should fail when the parameter store encounters an error")
}

func TestEncodePrivateKeyToPEM_Success(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rotator.DefaultKeySize)
	require.NoError(t, err, "Failed to generate RSA private key")

	encodedPEM := rotator.EncodePrivateKeyToPEM(privateKey)
	require.NotEmpty(t, encodedPEM, "Encoded PEM should not be empty")

	block, _ := pem.Decode(encodedPEM)
	require.NotNil(t, block, "Decoded PEM block should not be nil")
	assert.Equal(t, "RSA PRIVATE KEY", block.Type, "PEM block type should be 'RSA PRIVATE KEY'")
}

func TestEncodePrivateKeyToPEM_VariousKeySizes(t *testing.T) {
	keySizes := []int{rotator.MinKeySize, rotator.MaxKeySize}
	for _, size := range keySizes {
		privateKey, err := rsa.GenerateKey(rand.Reader, size)
		require.NoError(t, err, "Failed to generate RSA private key")

		encodedPEM := rotator.EncodePrivateKeyToPEM(privateKey)
		require.NotEmpty(t, encodedPEM, "Encoded PEM should not be empty for key size:", size)

		block, _ := pem.Decode(encodedPEM)
		require.NotNil(t, block, "Decoded PEM block should not be nil for key size:", size)
	}
}

func TestEncodePrivateKeyToPEM_NilPrivateKey(t *testing.T) {
	encodedPEM := rotator.EncodePrivateKeyToPEM(nil)
	assert.Empty(t, encodedPEM, "Encoded PEM should be empty for nil private key")
}

func TestEncodePublicKeyToPEM_Success(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rotator.DefaultKeySize)
	require.NoError(t, err, "Failed to generate RSA private key")

	publicKey := &privateKey.PublicKey
	encodedPEM, err := rotator.EncodePublicKeyToPEM(publicKey)
	require.NoError(t, err, "Failed to encode RSA public key to PEM")
	require.NotEmpty(t, encodedPEM, "Encoded PEM should not be empty")

	block, _ := pem.Decode(encodedPEM)
	require.NotNil(t, block, "Decoded PEM block should not be nil")
	assert.Equal(t, "RSA PUBLIC KEY", block.Type, "PEM block type should be 'RSA PUBLIC KEY'")
}

func TestEncodePublicKeyToPEM_VariousKeySizes(t *testing.T) {
	keySizes := []int{rotator.MinKeySize, rotator.MaxKeySize}
	for _, size := range keySizes {
		privateKey, err := rsa.GenerateKey(rand.Reader, size)
		require.NoError(t, err, "Failed to generate RSA private key")

		publicKey := &privateKey.PublicKey
		encodedPEM, err := rotator.EncodePublicKeyToPEM(publicKey)
		require.NoError(t, err, "Failed to encode RSA public key to PEM for key size:", size)
		require.NotEmpty(t, encodedPEM, "Encoded PEM should not be empty for key size:", size)
	}
}

func TestEncodePublicKeyToPEM_NilPublicKey(t *testing.T) {
	encodedPEM, err := rotator.EncodePublicKeyToPEM(nil)
	assert.Error(t, err, "Expected error when encoding nil public key to PEM")
	assert.Empty(t, encodedPEM, "Encoded PEM should be empty for nil public key")
}
