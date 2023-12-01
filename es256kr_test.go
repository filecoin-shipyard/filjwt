package filjwt_test

import (
	"crypto"
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/filecoin-shipyard/filjwt"
)

func TestSignedTokenIsValidECDSA(t *testing.T) {
	const sampleLotusWalletExport = "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226f784132746e774378426552303055734561766f56637551722b6d4133596b7346567543346254416873303d227d"
	_, privateKey, err := filjwt.Secp256k1KeyFromLotusWalletExport(sampleLotusWalletExport)
	if err != nil {
		t.Fatalf("faield to parse exported wallet: %v", err)
	}

	payload := "🐠"
	gotSignature, err := filjwt.SingingMethodES256KR.Sign(payload, privateKey)
	if err != nil {
		t.Fatalf("faield to sign: %v", err)
	}
	if len(gotSignature) != 32+32+1 {
		t.Fatalf("expected signature length of 65, 32 r, 32 s and 1 v, got: %d", len(gotSignature))
	}

	hasher := crypto.SHA256.New()
	hasher.Write([]byte(payload))

	r := new(big.Int)
	r.SetBytes(gotSignature[0:32]) // R
	s := new(big.Int)
	s.SetBytes(gotSignature[32:64]) // s
	verified := ecdsa.Verify(privateKey.PubKey().ToECDSA(), hasher.Sum(nil), r, s)
	if !verified {
		t.Fatalf("generated signture is not valid ECDSA")
	}
}
