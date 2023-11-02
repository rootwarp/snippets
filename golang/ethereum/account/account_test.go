package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/stretchr/testify/assert"
)

func TestCreateAccount(t *testing.T) {
	mnemonic, err := hdwallet.NewMnemonic(256)
	assert.Nil(t, err)

	seed, err := hdwallet.NewSeedFromMnemonic(mnemonic)
	assert.Nil(t, err)

	w, err := hdwallet.NewFromSeed(seed)
	assert.Nil(t, err)

	defer w.Close()

	hdPath, err := hdwallet.ParseDerivationPath("m/44'/60'/0'/0/1")
	assert.Nil(t, err)

	account, err := w.Derive(hdPath, false)
	assert.Nil(t, err)

	// Create address from public key
	pubKey, err := w.PublicKeyBytes(account)
	assert.Nil(t, err)

	sum := crypto.Keccak256Hash(pubKey[1:])
	derivedAddress := "0x" + hex.EncodeToString(sum.Bytes()[12:])

	assert.Equal(t, strings.ToLower(derivedAddress), strings.ToLower(account.Address.Hex()))

	// TODO: Create account from private key
	//
}
