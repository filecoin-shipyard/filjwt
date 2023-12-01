# :key: FilJWT

[![Go Reference](https://pkg.go.dev/badge/github.com/filecoin-shipyard/filjwt.svg)](https://pkg.go.dev/github.com/filecoin-shipyard/filjwt)
[![Go Test](https://github.com/filecoin-shipyard/filjwt/actions/workflows/go-test.yml/badge.svg)](https://github.com/filecoin-shipyard/filjwt/actions/workflows/go-test.yml)

> **Securely Generate JWT from Filecoin Wallet Address**

FilJWT is a Go package designed for the integration of Filecoin wallet addresses with JSON Web Tokens (JWT), specifically using the ES256K-R signing method. This package uniquely caters to Filecoin wallet addresses that follow the secp256k1 protocol.

## Features
- **ES256K-R Signing Method**: Implements the ES256K-R JWT signing method, where the ECDSA signature is deterministically generated as per RFC 6979. This signing method uses an additional byte at the signature's end, enabling the recovery of the public key directly from the JWT signature. The signature comprises 65 bytes: 32 bytes for R, 32 bytes for S, and 1 byte for V, arranged in R || S || V format.
- **Filecoin Wallet Address Compatibility**: Specifically designed to work with Filecoin wallet addresses that use the secp256k1 protocol. The package extracts these addresses from the 'kid' header of a JWT token for signature verification.
- **Secp256k1 Key Utility**: Includes a utility to convert a Lotus wallet export string into a Filecoin address and a secp256k1 private key, facilitating easy integration with Filecoin's wallet management.

## Usage

### Signing Method Registration
Upon initialization, FilJWT registers the custom ES256K-R signing method. This method can then be used with the `github.com/golang-jwt/jwt/v5` package for JWT operations.

### Key Functions
- `KIDAddrKeyFunc`: A `jwt.Keyfunc` for extracting and verifying a Filecoin wallet address (secp256k1 protocol only) from a JWT's 'kid' header.

### Signing and Verification
- `Sign`: Generates a signature for a given value using a secp256k1 private key.
- `Verify`: Confirms if a given signature corresponds to a given value and key, where the key is a secp256k1 public key, a Filecoin address, or a string representation of a Filecoin wallet address. Only addresses using the secp256k1 protocol are accepted.

### Algorithm Name
- `Alg`: Returns the algorithm name "ES256K-R".

### Lotus Wallet Export Utility
- `Secp256k1KeyFromLotusWalletExport`: Converts a Lotus wallet export string into a Filecoin address and a secp256k1 private key.

## Installation
Install FilJWT in your Go environment using:

```shell
go get -u github.com/filecoin-shipyard/filjwt
```

## Example
Example usage demonstrating the signing and verification of JWTs with FilJWT:

```go
package main

import (
	"fmt"

	"github.com/filecoin-shipyard/filjwt"
	"github.com/golang-jwt/jwt/v5"
)

func main() {
	// Sample Lotus wallet export string (replace with actual export)
	const sampleLotusWalletExport = "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226f784132746e774378426552303055734561766f56637551722b6d4133596b7346567543346254416873303d227d"

	// Convert Lotus wallet export to Filecoin address and private key
	addr, privateKey, err := filjwt.Secp256k1KeyFromLotusWalletExport(sampleLotusWalletExport)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Filecoin wallet address: %s\n", addr)

	// Create a new JWT token
	token := jwt.NewWithClaims(filjwt.SingingMethodES256KR, jwt.MapClaims{
		"iss": "filjwt-example",
	})
	token.Header["kid"] = addr.String()
	token.Header["crv"] = "secp256k1"

	// Sign the token using the private key
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Generated JWT token:\n  %s\n", signedToken)

	// Verify the generated token
	parsedToken, err := jwt.Parse(signedToken, func(_ *jwt.Token) (interface{}, error) {
		return addr, nil
	}, jwt.WithValidMethods([]string{filjwt.SingingMethodES256KR.Alg()}))
	if err != nil {
		panic(err)
	}
	fmt.Println("Successfully validated token:")
	fmt.Printf("  Issuer: %s\n", parsedToken.Claims.(jwt.MapClaims)["iss"])
}
```

For more examples see [`example_test.go`](./example_test.go).

## License
This project is dual-licensed under the MIT and Apache 2.0 licenses. For more details, consult the [LICENSE.md](LICENSE.md) file.
