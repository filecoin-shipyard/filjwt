package filjwt

import (
	"testing"

	"github.com/filecoin-project/go-address"
)

func TestSecp256k1KeyFromLotusWalletExport(t *testing.T) {
	tests := []struct {
		name     string
		given    string
		wantAddr string
		wantErr  bool
	}{
		{
			name:     "secp256k1",
			given:    "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a226f784132746e774378426552303055734561766f56637551722b6d4133596b7346567543346254416873303d227d",
			wantAddr: "t1yu5umbmxehc5w32svhlpruvsb5ml6ya7puvy4uq",
		},
		{
			name:    "bls",
			given:   "7b2254797065223a22626c73222c22507269766174654b6579223a22314f615368333576326e65756b654e76624e574231566d444c52357a6371534c6e6a6277756a6e4d426b453d227d",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAddr, gotPk, err := Secp256k1KeyFromLotusWalletExport(tt.given)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Secp256k1KeyFromLotusWalletExport() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if gotAddr.String() != tt.wantAddr {
					t.Fatalf("gotAddr = %v, wantAddr %v", gotAddr, tt.wantAddr)
				}
				gotAddrFromPrivateKey, err := address.NewSecp256k1Address(gotPk.PubKey().SerializeUncompressed())
				if err != nil {
					t.Fatalf("failed to generate address from private key %v", err)
				}
				if gotAddrFromPrivateKey.String() != tt.wantAddr {
					t.Fatalf("gotAddrFromPrivateKey = %v, wantAddr %v", gotAddr, tt.wantAddr)
				}
			}
		})
	}
}
