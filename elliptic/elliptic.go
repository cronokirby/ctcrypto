// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE_go file.

// Package elliptic implements several standard elliptic curves over prime
// fields.
package elliptic

// This package operates, internally, on Jacobian coordinates. For a given
// (x, y) position on the curve, the Jacobian coordinates are (x1, y1, z1)
// where x = x1/z1² and y = y1/z1³. The greatest speedups come when the whole
// calculation can be performed within the transform (as in ScalarMult and
// ScalarBaseMult). But even for Add and Double, it's faster to apply and
// reverse the transform than to operate in affine coordinates.

import (
	"io"
	"math/big"
	"sync"

	"github.com/cronokirby/safenum"
)

// A Curve represents a short-form Weierstrass curve with a=-3.
//
// Note that the point at infinity (0, 0) is not considered on the curve, and
// although it can be returned by Add, Double, ScalarMult, or ScalarBaseMult, it
// can't be marshaled or unmarshaled, and IsOnCurve will return false for it.
type Curve interface {
	// Params returns the parameters for the curve.
	Params() *CurveParams
	// IsOnCurve reports whether the given (x,y) lies on the curve.
	IsOnCurve(x, y *safenum.Nat) bool
	// Add returns the sum of (x1,y1) and (x2,y2)
	Add(x1, y1, x2, y2 *safenum.Nat) (x, y *safenum.Nat)
	// Double returns 2*(x,y)
	Double(x1, y1 *safenum.Nat) (x, y *safenum.Nat)
	// ScalarMult returns k*(Bx,By) where k is a number in big-endian form.
	ScalarMult(x1, y1 *safenum.Nat, k []byte) (x, y *safenum.Nat)
	// ScalarBaseMult returns k*G, where G is the base point of the group
	// and k is an integer in big-endian form.
	ScalarBaseMult(k []byte) (x, y *safenum.Nat)
}

// CurveParams contains the parameters of an elliptic curve and also provides
// a generic, non-constant time implementation of Curve.
type CurveParams struct {
	P       *safenum.Modulus // the order of the underlying field
	N       *safenum.Modulus // the order of the base point
	B       *safenum.Nat     // the constant of the curve equation
	Gx, Gy  *safenum.Nat     // (x,y) of the base point
	BitSize int              // the size of the underlying field
	Name    string           // the canonical name of the curve
}

func (curve *CurveParams) Params() *CurveParams {
	return curve
}

// polynomial returns x³ - 3x + b.
func (curve *CurveParams) polynomial(x *safenum.Nat) *safenum.Nat {
	x3 := new(safenum.Nat).ModMul(x, x, curve.P)
	x3.ModMul(x3, x, curve.P)

	threeX := new(safenum.Nat).ModAdd(x, x, curve.P)
	threeX.ModAdd(threeX, x, curve.P)

	x3.ModSub(x3, threeX, curve.P)
	x3.ModAdd(x3, curve.B, curve.P)

	return x3
}

func (curve *CurveParams) IsOnCurve(x, y *safenum.Nat) bool {
	// y² = x³ - 3x + b
	y2 := new(safenum.Nat).ModMul(y, y, curve.P)

	return curve.polynomial(x).Cmp(y2) == 0
}

// zForAffine returns a Jacobian Z value for the affine point (x, y). If x and
// y are zero, it assumes that they represent the point at infinity because (0,
// 0) is not on the any of the curves handled here.
func zForAffine(x, y *safenum.Nat) *safenum.Nat {
	z := new(safenum.Nat)
	if !x.EqZero() || !x.EqZero() {
		z.SetUint64(1)
	}
	return z
}

// affineFromJacobian reverses the Jacobian transform. See the comment at the
// top of the file. If the point is ∞ it returns 0, 0.
func (curve *CurveParams) affineFromJacobian(x, y, z *safenum.Nat) (xOut, yOut *safenum.Nat) {
	if z.EqZero() {
		return new(safenum.Nat), new(safenum.Nat)
	}

	zinv := new(safenum.Nat).ModInverse(z, curve.P)
	zinvsq := new(safenum.Nat).ModMul(zinv, zinv, curve.P)

	xOut = new(safenum.Nat).ModMul(x, zinvsq, curve.P)
	zinvsq.ModMul(zinvsq, zinv, curve.P)
	yOut = new(safenum.Nat).ModMul(y, zinvsq, curve.P)
	return
}

func (curve *CurveParams) Add(x1, y1, x2, y2 *safenum.Nat) (*safenum.Nat, *safenum.Nat) {
	z1 := zForAffine(x1, y1)
	z2 := zForAffine(x2, y2)
	return curve.affineFromJacobian(curve.addJacobian(x1, y1, z1, x2, y2, z2))
}

// addJacobian takes two points in Jacobian coordinates, (x1, y1, z1) and
// (x2, y2, z2) and returns their sum, also in Jacobian form.
func (curve *CurveParams) addJacobian(x1, y1, z1, x2, y2, z2 *safenum.Nat) (*safenum.Nat, *safenum.Nat, *safenum.Nat) {
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
	x3, y3, z3 := new(safenum.Nat), new(safenum.Nat), new(safenum.Nat)
	if z1.EqZero() {
		x3.SetNat(x2)
		y3.SetNat(y2)
		z3.SetNat(z2)
		return x3, y3, z3
	}
	if z2.EqZero() {
		x3.SetNat(x1)
		y3.SetNat(y1)
		z3.SetNat(z1)
		return x3, y3, z3
	}

	z1z1 := new(safenum.Nat).ModMul(z1, z1, curve.P)
	z2z2 := new(safenum.Nat).ModMul(z2, z2, curve.P)

	u1 := new(safenum.Nat).ModMul(x1, z2z2, curve.P)
	u2 := new(safenum.Nat).ModMul(x2, z1z1, curve.P)
	h := new(safenum.Nat).ModSub(u2, u1, curve.P)
	xEqual := h.EqZero()
	i := new(safenum.Nat).ModAdd(h, h, curve.P)
	i.ModMul(i, i, curve.P)
	j := new(safenum.Nat).ModMul(h, i, curve.P)

	s1 := new(safenum.Nat).ModMul(y1, z2, curve.P)
	s1.ModMul(s1, z2z2, curve.P)
	s2 := new(safenum.Nat).ModMul(y2, z1, curve.P)
	s2.ModMul(s2, z1z1, curve.P)
	r := new(safenum.Nat).ModSub(s2, s1, curve.P)
	yEqual := r.EqZero()
	if xEqual && yEqual {
		return curve.doubleJacobian(x1, y1, z1)
	}
	r.ModAdd(r, r, curve.P)
	v := new(safenum.Nat).ModMul(u1, i, curve.P)

	x3.SetNat(r)
	x3.ModMul(x3, x3, curve.P)
	x3.ModSub(x3, j, curve.P)
	x3.ModSub(x3, v, curve.P)
	x3.ModSub(x3, v, curve.P)

	y3.SetNat(r)
	v.ModSub(v, x3, curve.P)
	y3.ModMul(y3, v, curve.P)
	s1.ModMul(s1, j, curve.P)
	s1.ModAdd(s1, s1, curve.P)
	y3.ModSub(y3, s1, curve.P)

	z3.ModAdd(z1, z2, curve.P)
	z3.ModMul(z3, z3, curve.P)
	z3.ModSub(z3, z1z1, curve.P)
	z3.ModSub(z3, z2z2, curve.P)
	z3.ModMul(z3, h, curve.P)

	return x3, y3, z3
}

func (curve *CurveParams) Double(x1, y1 *safenum.Nat) (*safenum.Nat, *safenum.Nat) {
	z1 := zForAffine(x1, y1)
	return curve.affineFromJacobian(curve.doubleJacobian(x1, y1, z1))
}

// doubleJacobian takes a point in Jacobian coordinates, (x, y, z), and
// returns its double, also in Jacobian form.
func (curve *CurveParams) doubleJacobian(x, y, z *safenum.Nat) (*safenum.Nat, *safenum.Nat, *safenum.Nat) {
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
	delta := new(safenum.Nat).ModMul(z, z, curve.P)
	gamma := new(safenum.Nat).ModMul(y, y, curve.P)
	alpha := new(safenum.Nat).ModSub(x, delta, curve.P)
	alpha2 := new(safenum.Nat).ModAdd(x, delta, curve.P)
	alpha.ModMul(alpha, alpha2, curve.P)
	alpha2.SetNat(alpha)
	alpha.ModAdd(alpha, alpha, curve.P)
	alpha.ModAdd(alpha, alpha2, curve.P)

	beta := alpha2.ModMul(x, gamma, curve.P)

	x3 := new(safenum.Nat).ModMul(alpha, alpha, curve.P)
	eight := new(safenum.Nat).SetUint64(8)
	beta8 := new(safenum.Nat).ModMul(beta, eight, curve.P)
	x3.ModSub(x3, beta8, curve.P)

	z3 := new(safenum.Nat).ModAdd(y, z, curve.P)
	z3.ModMul(z3, z3, curve.P)
	z3.ModSub(z3, gamma, curve.P)
	z3.ModSub(z3, delta, curve.P)

	beta.ModMul(beta, new(safenum.Nat).SetUint64(4), curve.P)
	beta.ModSub(beta, x3, curve.P)
	y3 := alpha.ModMul(alpha, beta, curve.P)

	gamma.ModMul(gamma, gamma, curve.P)
	gamma.ModMul(gamma, eight, curve.P)

	y3.ModSub(y3, gamma, curve.P)

	return x3, y3, z3
}

func (curve *CurveParams) ScalarMult(Bx, By *safenum.Nat, k []byte) (*safenum.Nat, *safenum.Nat) {
	Bz := new(safenum.Nat).SetUint64(1)
	x, y, z := new(safenum.Nat), new(safenum.Nat), new(safenum.Nat)

	for _, byte := range k {
		for bitNum := 0; bitNum < 8; bitNum++ {
			x, y, z = curve.doubleJacobian(x, y, z)
			if byte&0x80 == 0x80 {
				x, y, z = curve.addJacobian(Bx, By, Bz, x, y, z)
			}
			byte <<= 1
		}
	}

	return curve.affineFromJacobian(x, y, z)
}

func (curve *CurveParams) ScalarBaseMult(k []byte) (*safenum.Nat, *safenum.Nat) {
	return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

var mask = []byte{0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f}

// GenerateKey returns a public/private key pair. The private key is
// generated using the given reader, which must return random data.
func GenerateKey(curve Curve, rand io.Reader) (priv []byte, x, y *safenum.Nat, err error) {
	N := curve.Params().N
	bitSize := N.BitLen()
	byteLen := (bitSize + 7) / 8
	priv = make([]byte, byteLen)

	for x == nil {
		_, err = io.ReadFull(rand, priv)
		if err != nil {
			return
		}
		// We have to mask off any excess bits in the case that the size of the
		// underlying field is not a whole number of bytes.
		priv[0] &= mask[bitSize%8]
		// This is because, in tests, rand will return all zeros and we don't
		// want to get the point at infinity and loop forever.
		priv[1] ^= 0x42

		// If the scalar is out of range, sample another random number.
		if new(safenum.Nat).SetBytes(priv).CmpMod(N) >= 0 {
			continue
		}

		x, y = curve.ScalarBaseMult(priv)
	}
	return
}

// Marshal converts a point on the curve into the uncompressed form specified in
// section 4.3.6 of ANSI X9.62.
func Marshal(curve Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) / 8

	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // uncompressed point

	x.FillBytes(ret[1 : 1+byteLen])
	y.FillBytes(ret[1+byteLen : 1+2*byteLen])

	return ret
}

// MarshalCompressed converts a point on the curve into the compressed form
// specified in section 4.3.6 of ANSI X9.62.
func MarshalCompressed(curve Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) / 8
	compressed := make([]byte, 1+byteLen)
	compressed[0] = byte(y.Bit(0)) | 2
	x.FillBytes(compressed[1:])
	return compressed
}

// Unmarshal converts a point, serialized by Marshal, into an x, y pair.
// It is an error if the point is not in uncompressed form or is not on the curve.
// On error, x = nil.
func Unmarshal(curve Curve, data []byte) (x, y *safenum.Nat) {
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(data) != 1+2*byteLen {
		return nil, nil
	}
	if data[0] != 4 { // uncompressed form
		return nil, nil
	}
	p := curve.Params().P
	x = new(safenum.Nat).SetBytes(data[1 : 1+byteLen])
	y = new(safenum.Nat).SetBytes(data[1+byteLen:])
	if x.CmpMod(p) >= 0 || y.CmpMod(p) >= 0 {
		return nil, nil
	}
	if !curve.IsOnCurve(x, y) {
		return nil, nil
	}
	return
}

// UnmarshalCompressed converts a point, serialized by MarshalCompressed, into an x, y pair.
// It is an error if the point is not in compressed form or is not on the curve.
// On error, x = nil.
func UnmarshalCompressed(curve Curve, data []byte) (x, y *safenum.Nat) {
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(data) != 1+byteLen {
		return nil, nil
	}
	if data[0] != 2 && data[0] != 3 { // compressed form
		return nil, nil
	}
	p := curve.Params().P
	x = new(safenum.Nat).SetBytes(data[1:])
	if x.CmpMod(p) >= 0 {
		return nil, nil
	}
	// y² = x³ - 3x + b
	y = curve.Params().polynomial(x)
	// TODO: Add methods for these shenanigans
	yBig := new(big.Int).SetBytes(y.Bytes())
	pBig := new(big.Int).SetBytes(p.Bytes())
	yBig.ModSqrt(yBig, pBig)
	if yBig == nil {
		return nil, nil
	}
	if byte(yBig.Bit(0)) != data[0]&1 {
		yBig.Neg(yBig).Mod(yBig, pBig)
	}
	y.SetBytes(yBig.Bytes())

	if !curve.IsOnCurve(x, y) {
		return nil, nil
	}
	return
}

var initonce sync.Once
var p384 *CurveParams
var p521 *CurveParams

func initAll() {
	initP224()
	initP256()
	initP384()
	initP521()
}

func fromString(s string, base int) (*safenum.Nat, bool) {
	num, ok := new(big.Int).SetString(s, base)
	if !ok {
		return nil, false
	}
	return new(safenum.Nat).SetBytes(num.Bytes()), true
}

func modulusFromString(s string, base int) (*safenum.Modulus, bool) {
	nat, ok := fromString(s, base)
	if !ok {
		return nil, false
	}
	return safenum.ModulusFromNat(*nat), true
}

func initP384() {
	// See FIPS 186-3, section D.2.4
	p384 = &CurveParams{Name: "P-384"}
	p384.P, _ = modulusFromString("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319", 10)
	p384.N, _ = modulusFromString("39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643", 10)
	p384.B, _ = fromString("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16)
	p384.Gx, _ = fromString("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16)
	p384.Gy, _ = fromString("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16)
	p384.BitSize = 384
}

func initP521() {
	// See FIPS 186-3, section D.2.5
	p521 = &CurveParams{Name: "P-521"}
	p521.P, _ = modulusFromString("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151", 10)
	p521.N, _ = modulusFromString("6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449", 10)
	p521.B, _ = fromString("051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16)
	p521.Gx, _ = fromString("c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16)
	p521.Gy, _ = fromString("11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16)
	p521.BitSize = 521
}

// P256 returns a Curve which implements NIST P-256 (FIPS 186-3, section D.2.3),
// also known as secp256r1 or prime256v1. The CurveParams.Name of this Curve is
// "P-256".
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func P256() Curve {
	initonce.Do(initAll)
	return p256
}

// P384 returns a Curve which implements NIST P-384 (FIPS 186-3, section D.2.4),
// also known as secp384r1. The CurveParams.Name of this Curve is "P-384".
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations do not use constant-time algorithms.
func P384() Curve {
	initonce.Do(initAll)
	return p384
}

// P521 returns a Curve which implements NIST P-521 (FIPS 186-3, section D.2.5),
// also known as secp521r1. The CurveParams.Name of this Curve is "P-521".
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations do not use constant-time algorithms.
func P521() Curve {
	initonce.Do(initAll)
	return p521
}
