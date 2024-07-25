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

func TestShamir(t *testing.T) {
	const (
		N = 5
		K = 3
	)
	// TODO: User merssene prime 2^127 - 1
	p := new(big.Int).SetInt64(2)
	p.Exp(p, big.NewInt(127), nil)
	p.Sub(p, big.NewInt(1))
	//p.Exp(p, big.NewInt(8), nil)

	var err error

	// Choose random secret
	secret, err := rand.Int(rand.Reader, p)
	assert.Nil(t, err)

	//secret = big.NewInt(10)
	fmt.Println("New secret is", secret)

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

	// TODO: Testing
	dummyX := []*big.Int{
		big.NewInt(7), big.NewInt(13), big.NewInt(19), big.NewInt(42), big.NewInt(97),
	}
	//

	shares := make([]secretShare, N)
	for i := 0; i < N; i++ {
		//x := new(big.Int).SetInt64(int64(i + 1)*1000)
		//x, err := rand.Int(rand.Reader, big.NewInt(100))
		//if err != nil {
		//	assert.Error(t, err)
		//}
		x := dummyX[i]

		y := new(big.Int)

		y.Add(y, coeffs[0])
		for j := 1; j < K; j++ {
			tmp := new(big.Int).Exp(x, big.NewInt(int64(j)), p)
			tmp.Mul(tmp, coeffs[j]).Mod(tmp, p)
			y.Add(y, tmp).Mod(y, p)
		}

		newShare := secretShare{X: x, Y: y}
		fmt.Println("share", newShare)
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

		lagN := new(big.Int)
		lagN.Div(numerator, denominator).Mod(lagN, p)

		lags[i] = lagN
	}

	// Sigma
	secretRecovered := new(big.Int).SetInt64(0)
	for i := 0; i < K; i++ {
		secretRecovered.Add(secretRecovered, new(big.Int).Mul(lags[i], shares[i].Y)).Mod(secretRecovered, p)
	}

	fmt.Println("Recovered secret is", secretRecovered.String())

	assert.Equal(t, secret.String(), secretRecovered.String())
}

func TestPolynomial(t *testing.T) {
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
