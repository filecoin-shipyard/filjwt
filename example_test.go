package filjwt_test

import (
	"fmt"

	"github.com/filecoin-shipyard/filjwt"
	"github.com/golang-jwt/jwt/v5"
)

// ExampleSingingMethodES256KR illustrates an example of JWT token generation and validation using Filecoin wallet private key and Filecoin wallet address.
func ExampleSingingMethodES256KR() {
	const sampleLotusWalletExport = "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226f784132746e774378426552303055734561766f56637551722b6d4133596b7346567543346254416873303d227d"

	addr, privateKey, err := filjwt.Secp256k1KeyFromLotusWalletExport(sampleLotusWalletExport)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Filecoin wallet address: %s\n", addr)

	token := jwt.NewWithClaims(filjwt.SingingMethodES256KR, jwt.MapClaims{
		"iss": "filjwt-example",
	})
	token.Header["kid"] = addr.String()
	token.Header["crv"] = "secp256k1"

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Generated JWT token:\n  %s\n", signedToken)

	// Verify the generated token
	parsedToken, err := jwt.Parse(signedToken, func(_ *jwt.Token) (any, error) {
		return addr, nil
	}, jwt.WithValidMethods([]string{filjwt.SingingMethodES256KR.Alg()}))
	if err != nil {
		panic(err)
	}
	fmt.Println("Successfully validated token:")
	fmt.Println("  Headers:")
	fmt.Printf("    alg:%v\n", parsedToken.Header["alg"])
	fmt.Printf("    crv:%v\n", parsedToken.Header["crv"])
	fmt.Printf("    kid:%v\n", parsedToken.Header["kid"])
	fmt.Printf("    typ:%v\n", parsedToken.Header["typ"])
	fmt.Println("  Claims:")
	issuer, err := parsedToken.Claims.GetIssuer()
	if err != nil {
		panic(err)
	}
	fmt.Printf("   exp:%v", issuer)

	// Output:
	// Filecoin wallet address: t1yu5umbmxehc5w32svhlpruvsb5ml6ya7puvy4uq
	// Generated JWT token:
	//   eyJhbGciOiJFUzI1NkstUiIsImNydiI6InNlY3AyNTZrMSIsImtpZCI6InQxeXU1dW1ibXhlaGM1dzMyc3ZobHBydXZzYjVtbDZ5YTdwdXZ5NHVxIiwidHlwIjoiSldUIn0.eyJpc3MiOiJmaWxqd3QtZXhhbXBsZSJ9.hWljo1gnf24RgF1p-TMhBev3x5JWQ1dzImRelcQd5lkaTRKmJzHyuqj89hrxZqcteXQPu845WsbsJ2_gpOlxpwE
	// Successfully validated token:
	//   Headers:
	//     alg:ES256K-R
	//     crv:secp256k1
	//     kid:t1yu5umbmxehc5w32svhlpruvsb5ml6ya7puvy4uq
	//     typ:JWT
	//   Claims:
	//    exp:filjwt-example
}
