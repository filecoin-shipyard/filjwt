package filjwt

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/filecoin-project/go-address"
)

func Secp256k1KeyFromLotusWalletExport(exp string) (address.Address, *secp256k1.PrivateKey, error) {
	decoded, err := hex.DecodeString(exp)
	if err != nil {
		return address.Address{}, nil, err
	}
	var k struct {
		Type       string
		PrivateKey []byte
	}
	if err := json.Unmarshal(decoded, &k); err != nil {
		return address.Address{}, nil, err
	}
	switch k.Type {
	case "secp256k1":
		priv := secp256k1.PrivKeyFromBytes(k.PrivateKey)
		addr, err := address.NewSecp256k1Address(priv.PubKey().SerializeUncompressed())
		return addr, priv, err
	default:
		return address.Address{}, nil, fmt.Errorf("key must be of type secp256k1, got: %s", k.Type)
	}
}
