# Go Key Rotator

## Overview

`go_key_rotator` is a Go package designed for robust RSA key management. It facilitates generating, rotating, and encoding RSA private keys, and integrates seamlessly with AWS Parameter Store for secure key storage and retrieval. This package is particularly useful for applications that require cryptographic operations like token signing and data encryption.

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
    "go_key_rotator" // replace with the actual import path
)

func main() {
    // Example: Using go_key_rotator for RSA key management

    // Rotate the RSA key and store the new key in AWS Parameter Store
    newKey, err := go_key_rotator.RotatePrivateKey()
    if err != nil {
        log.Fatalf("Failed to rotate private key: %v", err)
    }
    log.Println("New RSA private key generated and stored.")

    // Retrieve the current RSA private key for use in cryptographic operations
    currentKey, err := go_key_rotator.GetCurrentRSAKey()
    if err != nil {
        log.Fatalf("Failed to retrieve current private key: %v", err)
    }
    log.Println("Retrieved current RSA private key.")
}
```

---

## Contributing

🤝 We welcome contributions to `go_key_rotator`! Whether it's fixing bugs, improving 
documentation, or suggesting new features, your input is valuable. Here's how you can 
contribute:

### Fork the Repository

1. **Fork the Repository**: Navigate to the `go_key_rotator` GitHub repository and click 
the "Fork" button in the top-right corner. This creates a copy of the repo in your own 
GitHub account.

2. **Clone Your Fork**: Clone your forked repository to your local machine:
   ```bash
   git clone https://github.com/your-username/go_key_rotator.git
   cd go_key_rotator
   ```

3. **Set Upstream Remote**: Add the original `go_key_rotator` repository as an "upstream" remote to your local clone:

   ```bash
   git remote add upstream https://github.com/original-username/go_key_rotator.git
   ```

### Create a New Branch

Create a new branch for your changes. It helps isolate your contribution:

```bash
git checkout -b feature/your-awesome-feature
```

### Make Your Changes

1. **Code**: Make your changes to the code. Be sure to adhere to the existing 
coding style and add comments as necessary.

2. **Commit**: Commit your changes with a clear and descriptive commit message:

   ```bash
   git commit -am "Add a brief description of your changes"
   ```

### Keep Your Branch Updated

Regularly sync your branch with the main branch to keep it up-to-date:

```bash
git fetch upstream
git rebase upstream/main
```

### Push Your Changes and Create a Pull Request

1. **Push**: Push your changes to your GitHub repository:

```bash
git push origin feature/your-awesome-feature
```

2. **Pull Request**: Open a pull request from your feature branch to the main branch of the original `go_key_rotator` repository. Provide a clear description of your changes and how they improve the project.

# License
`go_key_rotator` is released under the MIT License.
