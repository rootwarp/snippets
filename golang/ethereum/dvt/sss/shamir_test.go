package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

type secretShare struct {
	X *big.Int
	Y *big.Int
}

func TestShamirSecretSharing(t *testing.T) {
	const (
		N = 5
		K = 3
	)

	p := new(big.Int).SetInt64(2)
	p.Exp(p, big.NewInt(127), nil)
	p.Sub(p, big.NewInt(1))

	secret, err := rand.Int(rand.Reader, p)
	assert.Nil(t, err)

	// Random polynomial
	coeffs := make([]*big.Int, K)
	coeffs[0] = secret

	for i := 1; i < K; i++ {
		coeffs[i], err = rand.Int(rand.Reader, p)
		assert.Nil(t, err)
	}

	polynomial := NewPolynomial(coeffs, p)

	// Create partial secrets
	shares := make([]secretShare, N)
	for i := 0; i < N; i++ {
		x, err := rand.Int(rand.Reader, p)
		assert.Nil(t, err)

		y := polynomial.Eval(x)

		newShare := secretShare{X: x, Y: y}
		fmt.Println("share", newShare)
		shares[i] = newShare
	}

	// Recover secret. Use Lagrange interpolation
	lags := make([]*big.Int, K)
	for i := 0; i < K; i++ {
		curX := shares[i].X

		numerator := new(big.Int).SetInt64(1)
		denominator := new(big.Int).SetInt64(1)
		for j := 0; j < K; j++ {
			if i == j {
				continue
			}

			numerator.Mul(numerator, new(big.Int).Sub(big.NewInt(0), shares[j].X))
			denominator.Mul(denominator, new(big.Int).Sub(curX, shares[j].X))
		}

		lagN := new(big.Int)
		lagN.ModInverse(denominator, p)
		lagN.Mul(lagN, numerator)

		lags[i] = lagN
	}

	// Sigma
	secretRecovered := new(big.Int).SetInt64(0)
	for i := 0; i < K; i++ {
		secretRecovered.Add(secretRecovered, new(big.Int).Mul(lags[i], shares[i].Y)).Mod(secretRecovered, p)
	}

	fmt.Println("Original secret is", secret.String())
	fmt.Println("Recovered secret is", secretRecovered.String())

	assert.Equal(t, secret.String(), secretRecovered.String())
}
