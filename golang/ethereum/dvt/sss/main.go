package main

import (
	"math/big"
)

type Polynomial struct {
	coeffs []*big.Int
	p      *big.Int
}

func (p *Polynomial) Eval(x *big.Int) *big.Int {
	y := new(big.Int)
	y.Set(p.coeffs[0])
	xpow := new(big.Int).Set(x)
	for i := 1; i < len(p.coeffs); i++ {
		xi := new(big.Int)
		xi.Mul(p.coeffs[i], xpow).Mod(xi, p.p)

		y.Add(y, xi).Mod(y, p.p)
		xpow.Mul(xpow, x)
	}
	return y
}

func (p *Polynomial) Order() int {
	return len(p.coeffs) - 1
}

func NewPolynomial(coeffs []*big.Int, p *big.Int) *Polynomial {
	return &Polynomial{
		coeffs: coeffs,
		p:      p,
	}
}

func main() {
}
