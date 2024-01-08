# Go Key Rotator

## Overview

`go_key_rotator` is a Go package designed for robust RSA key management. It
facilitates generating, rotating, and encoding RSA private keys, and integrates
seamlessly with AWS Parameter Store for secure key storage and retrieval. This
package is particularly useful for applications that require cryptographic
operations like token signing and data encryption.

## Features

- RSA key pair generation
- PEM encoding for RSA keys
- Secure storage and retrieval of keys via AWS Parameter Store
- Automatic key rotation for enhanced security

## Installation

To install `go_key_rotator`, use the `go get` command:

```bash
go get github.com/your_username/go_key_rotator
```

This will download the package along with its dependencies.

## Usage

Here's a simple example of how to use `go_key_rotator`:

```go
package main

import (
   "log"
   "github.com/kmesiab/go_key_rotator"
)

func main() {
	// Example: Using go_key_rotator for RSA key management

	// Rotate the RSA key and store the new key in AWS Parameter Store
	newPrivateKey, newPublicKey, err := go_key_rotator.RotatePrivateKeyAndPublicKey()
	
	if err != nil {
		log.Fatalf("Failed to rotate private key: %v", err)
	}
	
	log.Println("New RSA keys generated and stored.")
}
```

### Get the current keys:

```go
   currentPrivateKey, err := go_key_rotator.GetCurrentRSAPrivateKey()
   if err != nil {
      log.Fatalf("Failed to retrieve current private key: %v", err)
   }

   currentPublicKey, err := go_key_rotator.GetCurrentRSAPublicKey()
   if err != nil {
      log.Fatalf("Failed to retrieve current public key: %v", err)
   }
}
```
