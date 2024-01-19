# Go Key Rotator 🔐

![Golang](https://img.shields.io/badge/Go-00add8.svg?labelColor=171e21&style=for-the-badge&logo=go)
[![License](https://img.shields.io/github/license/GitGuardian/ggshield?color=%231B2D55&style=for-the-badge)](LICENSE)

![Build](https://github.com/kmesiab/go-key-rotator/actions/workflows/go-build.yml/badge.svg)
![Lint](https://github.com/kmesiab/go-key-rotator/actions/workflows/go-lint.yml/badge.svg)
![Test](https://github.com/kmesiab/go-key-rotator/actions/workflows/go-test.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/kmesiab/go-key-rotator)](https://goreportcard.com/report/github.com/kmesiab/go-key-rotator)

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
go get github.com/kmesiab/go_key_rotator
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

   // Create a rotator and give it a ParameterStoreInterface
   keyRotator := rotator.NewKeyRotator(
      rotator.NewAWSParameterStore(sess),
   )

   // Call Rotate and tell it where to store your keys
   // how big to make them
   privateKey, publicKey, err = keyRotator.Rotate(
      psPrivateKeyName, psPublicKeyName, 2048,
   )   
   
   if err != nil {
      log.Fatalf("Failed to rotate private key: %v", err)
   }
   
   log.Println("New RSA keys generated and stored.")
}
```

### Get the current keys

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
