package go_key_rotator

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
)

type ParameterStoreInterface interface {
	GetParameter(name string) (string, error)
	PutParameter(name, value, parameterType string) error
}

// AWSParameterStore is an implementation of the ParameterStoreInterface that interfaces with the AWS Parameter Store.
// This struct encapsulates an AWS session, which is used to interact with the AWS Simple Systems Manager (SSM) service
// for retrieving and storing parameters securely. AWS Parameter Store offers a centralized solution for managing
// configuration data and secrets, which is essential in applications requiring secure and scalable storage solutions.
//
// The AWSParameterStore struct is designed to be used in scenarios where real interactions with AWS services are
// necessary, such as production environments or integration testing. By implementing the ParameterStoreInterface,
// it provides a standardized way to interact with parameter store services, ensuring consistency and ease of use
// in managing application configurations and secrets.
//
// Fields:
// - Session: An AWS session used to create an SSM service client for Parameter Store interactions.
//
// Usage:
// Create an instance of AWSParameterStore with an initialized AWS session to perform operations like
// retrieving and storing RSA keys or other sensitive configuration data in the AWS Parameter Store.
type AWSParameterStore struct {
	Session *session.Session
}

// NewAWSParameterStore creates and returns a new instance of AWSParameterStore.
// This function accepts an AWS session and returns an AWSParameterStore struct that
// implements the ParameterStoreInterface. The returned instance is used to interact
// with the AWS Parameter Store service, allowing for the storage and retrieval of
// parameters such as configuration settings or cryptographic keys.
//
// Parameters:
//   - session: An initialized AWS session that provides the necessary configuration
//     and credentials for accessing AWS services.
//
// Returns:
//   - ParameterStoreInterface: An instance of AWSParameterStore which can be used
//     to interact with the AWS Parameter Store.
//
// Usage:
// Use this function to create an AWSParameterStore instance when you need to perform
// operations on the AWS Parameter Store in your application. This is particularly useful
// for scenarios requiring direct interaction with AWS services for parameter management.
func NewAWSParameterStore(session *session.Session) ParameterStoreInterface {
	return AWSParameterStore{
		Session: session,
	}
}

// GetParameter retrieves a value from AWS Parameter Store.
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
func (p AWSParameterStore) GetParameter(name string) (string, error) {

	var (
		err   error
		param *ssm.GetParameterOutput
	)

	svc := ssm.New(p.Session)
	input := &ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(true),
	}

	if param, err = svc.GetParameter(input); err != nil {
		return "", err
	}

	return *param.Parameter.Value, nil
}

// PutParameter stores a given value in the AWS Parameter Store.
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
func (p AWSParameterStore) PutParameter(parameterName, value, parameterType string) error {

	svc := ssm.New(p.Session)
	input := &ssm.PutParameterInput{
		Name:      aws.String(parameterName),
		Value:     aws.String(value),
		Type:      aws.String(parameterType),
		Overwrite: aws.Bool(true),
	}

	_, err := svc.PutParameter(input)

	return err
}

// MockParameterStore is a mock implementation of the ParameterStoreInterface
// used for testing purposes. It simulates the behavior of a parameter store
// by using an in-memory map to store parameter values.
//
// Functions:
//   - NewMockParameterStore: Initializes and returns a new instance of MockParameterStore.
//   - GetParameter: Retrieves a parameter value by its name. If the parameter exists,
//     returns its value; otherwise, returns an empty string and an error.
//   - PutParameter: Stores a parameter value by its name. The parameterType argument
//     is ignored in this mock implementation as the main purpose is to
//     simulate storage and retrieval of parameter values.
//
// Usage:
// Use MockParameterStore in unit tests to replace actual AWS Parameter Store interactions.
// This allows for testing the behavior of your application logic without the need for
// external dependencies and network calls.

// MockParameterStore with error simulation capability
type MockParameterStore struct {
	Parameters    map[string]string
	simulateError bool
}

// NewMockParameterStore creates and returns a new instance of MockParameterStore.
// It initializes the Parameters map, ready to be used for storing and retrieving parameters.
func NewMockParameterStore(simulateError bool) *MockParameterStore {
	return &MockParameterStore{
		simulateError: simulateError,
		Parameters:    make(map[string]string),
	}
}

func (m *MockParameterStore) GetParameter(name string) (string, error) {

	return m.Parameters[name], nil
}

func (m *MockParameterStore) PutParameter(name, value, _ string) error {
	if m.simulateError {
		return fmt.Errorf("simulated parameter store error")
	}
	m.Parameters[name] = value
	return nil
}

func (m *MockParameterStore) SimulateError(simulate bool) {
	m.simulateError = simulate
}
