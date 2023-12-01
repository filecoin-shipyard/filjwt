package filjwt

import (
	"bytes"
	"crypto"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/filecoin-project/go-address"
	"github.com/golang-jwt/jwt/v5"
)

var (
	// SingingMethodES256KR represents the ES256K-R JWT signing method, where the ECDSA signature is generated using the deterministic scheme as described by RFC 6979.
	// This signing method uses an extra byte at the end of the signature, which allows the public key to be recoverable from the
	// signature, making a total length of 65 byte signatures: 32 byte R, 32 byte S and 1 byte V in R || S || V format.
	SingingMethodES256KR jwt.SigningMethod

	// KIDAddrKeyFunc extracts Filecoin wallet address from 'kid' header of a JWT token and uses it to verify the token signature.
	// See jwt.Keyfunc, jwt.Parse.
	KIDAddrKeyFunc jwt.Keyfunc = func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"]
		if !ok {
			return nil, jwt.ErrTokenInvalidId
		}
		addr, ok := kid.(string)
		if !ok {
			return nil, jwt.ErrTokenInvalidId
		}
		return addr, nil
	}
)

type es256kr struct{}

func init() {
	SingingMethodES256KR = new(es256kr)
	jwt.RegisterSigningMethod(SingingMethodES256KR.Alg(), func() jwt.SigningMethod {
		return SingingMethodES256KR
	})
}

// Sign produces signature for the given value, signed using the specified key.
// The key type must be secp256k1.PrivateKey.
func (s *es256kr) Sign(value string, key any) ([]byte, error) {
	// Get the key
	var ecdsaKey *secp256k1.PrivateKey
	switch k := key.(type) {
	case *secp256k1.PrivateKey:
		ecdsaKey = k
	default:
		return nil, jwt.ErrInvalidKeyType
	}

	hasher := crypto.SHA256.New() // TODO use pooled hashers
	hasher.Write([]byte(value))
	sig := ecdsa.SignCompact(ecdsaKey, hasher.Sum(nil), false)

	// Compact signature format is <1-byte compact sig recovery code><32-byte R><32-byte S>
	// Move recovery code to the end in order to comply with ES256K-R JWT format of R || S || V
	v := sig[0]
	copy(sig, sig[1:])
	sig[64] = v - 27

	return sig, nil
}

// Verify verifies the signature for the given value corresponds to the given key.
// The key type must be one of secp256k1.PublicKey, address.Address, or string representation of a filecoin wallet address.
// Only address.SECP256K1 protocol (i.e. f1 address) is accepted.
func (s *es256kr) Verify(value string, sig []byte, key any) error {
	var addr address.Address
	var err error
	switch k := key.(type) {
	case *secp256k1.PublicKey:
		addr, err = address.NewSecp256k1Address(k.SerializeUncompressed())
		if err != nil || addr.Protocol() != address.SECP256K1 {
			return jwt.ErrInvalidKeyType
		}
	case address.Address:
		addr = k
		if addr.Protocol() != address.SECP256K1 {
			return jwt.ErrInvalidKeyType
		}
	case string:
		addr, err = address.NewFromString(k)
		if err != nil || addr.Protocol() != address.SECP256K1 {
			return jwt.ErrInvalidKeyType
		}
	default:
		return jwt.ErrInvalidKeyType
	}
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(value))

	// Restore format to what RecoverCompact expects
	v := sig[64] + 27
	copy(sig[1:], sig)
	sig[0] = v

	pub, _, err := ecdsa.RecoverCompact(sig, hasher.Sum(nil))
	if err != nil {
		return jwt.ErrECDSAVerification
	}
	recoveredAddr, err := address.NewSecp256k1Address(pub.SerializeUncompressed())
	if err != nil {
		return jwt.ErrECDSAVerification
	}
	if !bytes.Equal(recoveredAddr.Payload(), addr.Payload()) {
		return jwt.ErrECDSAVerification
	}
	return nil
}

func (s *es256kr) Alg() string {
	return "ES256K-R"
}
