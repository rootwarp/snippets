package main

import (
	"fmt"
	"math/big"
	"testing"
	"crypto/rand"

	"github.com/stretchr/testify/assert"
)

type secretShare struct {
	X *big.Int
	Y *big.Int
}

func TestShamir(t *testing.T) {
	const (
		N = 5
		K = 3
	)
	// TODO: User merssene prime 2^127 - 1
	p := new(big.Int).SetInt64(2)
	p.Exp(p, big.NewInt(127), nil)

	var err error

	// Choose random secret
	secret, err := rand.Int(rand.Reader, p)
	assert.Nil(t, err)

	fmt.Println("New secret is", secret)
	//secret := big.NewInt(10)

	coeffs := make([]*big.Int, K)
	coeffs[0] = secret

	// Create random polynomial
	for i := 1; i < K; i++ {
		coeffs[i], err = rand.Int(rand.Reader, p)
		//coeffs[i] = big.NewInt(int64(i))
		assert.Nil(t, err)
	}

	fmt.Println("created polynomial", coeffs)

	// Generate shares
	shares := make([]secretShare, N)
	for i := 0; i < N; i++ {
		x := new(big.Int).SetInt64(int64(i + 1))
		y := new(big.Int)

		y.Add(y, coeffs[0])
		for j := 1; j < K; j++ {
			tmp := new(big.Int).Exp(x, big.NewInt(int64(j)), nil)
			tmp.Mul(tmp, coeffs[j])
			y.Add(y, tmp)
		}
		newShare := secretShare{X: x, Y: y}
		shares[i] = newShare
	}
	//

	fmt.Println("=====")

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

		lagN := new(big.Int).Div(numerator, denominator)
		lags[i] = lagN
	}

	// Sigma
	secretRecovered := new(big.Int).SetInt64(0)
	for i := 0; i < K; i++ {
		secretRecovered.Add(secretRecovered, new(big.Int).Mul(lags[i], shares[i].Y))
	}

	fmt.Println("Recovered secret is", secretRecovered.String())

	assert.Equal(t, secret.String(), secretRecovered.String())
}
