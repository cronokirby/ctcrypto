// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package rsa implements RSA encryption as specified in PKCS #1 and RFC 8017.
//
// RSA is a single, fundamental operation that is used in this package to
// implement either public-key encryption or public-key signatures.
//
// The original specification for encryption and signatures with RSA is PKCS #1
// and the terms "RSA encryption" and "RSA signatures" by default refer to
// PKCS #1 version 1.5. However, that specification has flaws and new designs
// should use version 2, usually called by just OAEP and PSS, where
// possible.
//
// Two sets of interfaces are included in this package. When a more abstract
// interface isn't necessary, there are functions for encrypting/decrypting
// with v1.5/OAEP and signing/verifying with v1.5/PSS. If one needs to abstract
// over the public key primitive, the PrivateKey type implements the
// Decrypter and Signer interfaces from the crypto package.
//
// The RSA operations in this package are not implemented using constant-time algorithms.
package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"math"

	"github.com/cronokirby/ctcrypto/internal/randutil"
	"github.com/cronokirby/safenum"
)

// A PublicKey represents the public part of an RSA key.
type PublicKey struct {
	N *safenum.Modulus // modulus
	E int              // public exponent
}

// Any methods implemented on PublicKey might need to also be implemented on
// PrivateKey, as the latter embeds the former and will expose its methods.

// Size returns the modulus size in bytes. Raw signatures and ciphertexts
// for or by this public key will have the same size.
func (pub *PublicKey) Size() int {
	return int((pub.N.BitLen() + 7) / 8)
}

// Equal reports whether pub and x have the same value.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey)
	if !ok {
		return false
	}
	return pub.N.Cmp(xx.N) == 0 && pub.E == xx.E
}

// OAEPOptions is an interface for passing options to OAEP decryption using the
// crypto.Decrypter interface.
type OAEPOptions struct {
	// Hash is the hash function that will be used when generating the mask.
	Hash crypto.Hash
	// Label is an arbitrary byte string that must be equal to the value
	// used when encrypting.
	Label []byte
}

var (
	errPublicModulus       = errors.New("crypto/rsa: missing public modulus")
	errPublicExponentSmall = errors.New("crypto/rsa: public exponent too small")
	errPublicExponentLarge = errors.New("crypto/rsa: public exponent too large")
)

// checkPub sanity checks the public key before we use it.
// We require pub.E to fit into a 32-bit integer so that we
// do not have different behavior depending on whether
// int is 32 or 64 bits. See also
// https://www.imperialviolet.org/2012/03/16/rsae.html.
func checkPub(pub *PublicKey) error {
	if pub.N == nil {
		return errPublicModulus
	}
	if pub.E < 2 {
		return errPublicExponentSmall
	}
	if pub.E > 1<<31-1 {
		return errPublicExponentLarge
	}
	return nil
}

// A PrivateKey represents an RSA key
type PrivateKey struct {
	PublicKey                // public part.
	D         *safenum.Nat   // private exponent
	Primes    []*safenum.Nat // prime factors of N, has >= 2 elements.

	// Precomputed contains precomputed values that speed up private
	// operations, if available.
	Precomputed PrecomputedValues
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

// Equal reports whether priv and x have equivalent values. It ignores
// Precomputed values.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	if !priv.PublicKey.Equal(&xx.PublicKey) || priv.D.Cmp(xx.D) != 0 {
		return false
	}
	if len(priv.Primes) != len(xx.Primes) {
		return false
	}
	for i := range priv.Primes {
		if priv.Primes[i].Cmp(xx.Primes[i]) != 0 {
			return false
		}
	}
	return true
}

// Sign signs digest with priv, reading randomness from rand. If opts is a
// *PSSOptions then the PSS algorithm will be used, otherwise PKCS #1 v1.5 will
// be used. digest must be the result of hashing the input message using
// opts.HashFunc().
//
// This method implements crypto.Signer, which is an interface to support keys
// where the private part is kept in, for example, a hardware module. Common
// uses should use the Sign* functions in this package directly.
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if pssOpts, ok := opts.(*PSSOptions); ok {
		return SignPSS(rand, priv, pssOpts.Hash, digest, pssOpts)
	}

	return SignPKCS1v15(priv, opts.HashFunc(), digest)
}

// Decrypt decrypts ciphertext with priv. If opts is nil or of type
// *PKCS1v15DecryptOptions then PKCS #1 v1.5 decryption is performed. Otherwise
// opts must have type *OAEPOptions and OAEP decryption is done.
func (priv *PrivateKey) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	if opts == nil {
		return DecryptPKCS1v15(priv, ciphertext)
	}

	switch opts := opts.(type) {
	case *OAEPOptions:
		return DecryptOAEP(opts.Hash.New(), priv, ciphertext, opts.Label)

	case *PKCS1v15DecryptOptions:
		if l := opts.SessionKeyLen; l > 0 {
			plaintext = make([]byte, l)
			if _, err := io.ReadFull(rand, plaintext); err != nil {
				return nil, err
			}
			if err := DecryptPKCS1v15SessionKey(priv, ciphertext, plaintext); err != nil {
				return nil, err
			}
			return plaintext, nil
		} else {
			return DecryptPKCS1v15(priv, ciphertext)
		}

	default:
		return nil, errors.New("crypto/rsa: invalid options for Decrypt")
	}
}

type PrecomputedValues struct {
	Dp, Dq *safenum.Nat // D mod (P-1) (or mod Q-1)
	Qinv   *safenum.Nat // Q^-1 mod P

	// CRTValues is used for the 3rd and subsequent primes. Due to a
	// historical accident, the CRT for the first two primes is handled
	// differently in PKCS #1 and interoperability is sufficiently
	// important that we mirror this.
	CRTValues []CRTValue
}

// CRTValue contains the precomputed Chinese remainder theorem values.
type CRTValue struct {
	Exp   *safenum.Nat // D mod (prime-1).
	Coeff *safenum.Nat // R·Coeff ≡ 1 mod Prime.
	R     *safenum.Nat // product of primes prior to this (inc p and q).
}

// Validate performs basic sanity checks on the key.
// It returns nil if the key is valid, or else an error describing a problem.
func (priv *PrivateKey) Validate() error {
	if err := checkPub(&priv.PublicKey); err != nil {
		return err
	}

	// Check that Πprimes == n.
	one := new(safenum.Nat).SetUint64(1)
	modulus := new(safenum.Nat).SetUint64(1)
	for _, prime := range priv.Primes {
		// Any primes ≤ 1 will cause divide-by-zero panics later.
		if prime.Cmp(one) <= 0 {
			return errors.New("crypto/rsa: invalid prime value")
		}
		modulus.Mul(modulus, prime, priv.N.BitLen())
	}
	if modulus.CmpMod(priv.N) != 0 {
		return errors.New("crypto/rsa: invalid modulus")
	}

	// Check that de ≡ 1 mod p-1, for each prime.
	// This implies that e is coprime to each p-1 as e has a multiplicative
	// inverse. Therefore e is coprime to lcm(p-1,q-1,r-1,...) =
	// exponent(ℤ/nℤ). It also implies that a^de ≡ a mod p as a^(p-1) ≡ 1
	// mod p. Thus a^de ≡ a mod n for all a coprime to n, as required.
	congruence := new(safenum.Nat)
	de := new(safenum.Nat).SetUint64(uint64(priv.E))
	de.Mul(de, priv.D, priv.D.AnnouncedLen()+64)
	for _, prime := range priv.Primes {
		pminus1 := new(safenum.Nat).Sub(prime, one, priv.N.BitLen())
		congruence.Mod(de, safenum.ModulusFromNat(*pminus1))
		if congruence.Cmp(one) != 0 {
			return errors.New("crypto/rsa: invalid exponents")
		}
	}
	return nil
}

// GenerateKey generates an RSA keypair of the given bit size using the
// random source random (for example, crypto/rand.Reader).
func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	return GenerateMultiPrimeKey(random, 2, bits)
}

// GenerateMultiPrimeKey generates a multi-prime RSA keypair of the given bit
// size and the given random source, as suggested in [1]. Although the public
// keys are compatible (actually, indistinguishable) from the 2-prime case,
// the private keys are not. Thus it may not be possible to export multi-prime
// private keys in certain formats or to subsequently import them into other
// code.
//
// Table 1 in [2] suggests maximum numbers of primes for a given size.
//
// [1] US patent 4405829 (1972, expired)
// [2] http://www.cacr.math.uwaterloo.ca/techreports/2006/cacr2006-16.pdf
func GenerateMultiPrimeKey(random io.Reader, nprimes int, bits int) (*PrivateKey, error) {
	randutil.MaybeReadByte(random)

	priv := new(PrivateKey)
	priv.E = 65537

	if nprimes < 2 {
		return nil, errors.New("crypto/rsa: GenerateMultiPrimeKey: nprimes must be >= 2")
	}

	if bits < 64 {
		primeLimit := float64(uint64(1) << uint(bits/nprimes))
		// pi approximates the number of primes less than primeLimit
		pi := primeLimit / (math.Log(primeLimit) - 1)
		// Generated primes start with 11 (in binary) so we can only
		// use a quarter of them.
		pi /= 4
		// Use a factor of two to ensure that key generation terminates
		// in a reasonable amount of time.
		pi /= 2
		if pi <= float64(nprimes) {
			return nil, errors.New("crypto/rsa: too few primes of given length to generate an RSA key")
		}
	}

	primes := make([]*safenum.Nat, nprimes)

NextSetOfPrimes:
	for {
		todo := bits
		// crypto/rand should set the top two bits in each prime.
		// Thus each prime has the form
		//   p_i = 2^bitlen(p_i) × 0.11... (in base 2).
		// And the product is:
		//   P = 2^todo × α
		// where α is the product of nprimes numbers of the form 0.11...
		//
		// If α < 1/2 (which can happen for nprimes > 2), we need to
		// shift todo to compensate for lost bits: the mean value of 0.11...
		// is 7/8, so todo + shift - nprimes * log2(7/8) ~= bits - 1/2
		// will give good results.
		if nprimes >= 7 {
			todo += (nprimes - 2) / 5
		}
		for i := 0; i < nprimes; i++ {
			primesIBig, err := rand.Prime(random, todo/(nprimes-i))
			primes[i] = new(safenum.Nat).SetBytes(primesIBig.Bytes())
			if err != nil {
				return nil, err
			}
			todo -= int(primes[i].TrueLen())
		}

		// Make sure that primes is pairwise unequal.
		for i, prime := range primes {
			for j := 0; j < i; j++ {
				if prime.Cmp(primes[j]) == 0 {
					continue NextSetOfPrimes
				}
			}
		}

		one := new(safenum.Nat).SetUint64(1)
		n := new(safenum.Nat).SetUint64(1)
		totient := new(safenum.Nat).SetUint64(1)
		pminus1 := new(safenum.Nat)
		for _, prime := range primes {
			n.Mul(n, prime, uint(bits))
			pminus1.Sub(prime, one, prime.TrueLen())
			totient.Mul(totient, pminus1, uint(bits))
		}
		if int(n.TrueLen()) != bits {
			// This should never happen for nprimes == 2 because
			// crypto/rand should set the top two bits in each prime.
			// For nprimes > 2 we hope it does not happen often.
			continue NextSetOfPrimes
		}

		e := new(safenum.Nat).SetUint64(uint64(priv.E))
		// NOTE: In case priv.E is badly chosen, this can silently fail
		priv.D = new(safenum.Nat)
		ok := priv.D.ModInverseEven(e, totient)

		if ok != nil {
			priv.Primes = make([]*safenum.Nat, len(primes))
			for i := 0; i < len(primes); i++ {
				priv.Primes[i] = new(safenum.Nat).SetBytes(primes[i].Bytes())
			}
			priv.N = safenum.ModulusFromBytes(n.Bytes())
			break
		}
	}

	priv.Precompute()
	return priv, nil
}

// incCounter increments a four byte, big-endian counter.
func incCounter(c *[4]byte) {
	if c[3]++; c[3] != 0 {
		return
	}
	if c[2]++; c[2] != 0 {
		return
	}
	if c[1]++; c[1] != 0 {
		return
	}
	c[0]++
}

// mgf1XOR XORs the bytes in out with a mask generated using the MGF1 function
// specified in PKCS #1 v2.1.
func mgf1XOR(out []byte, hash hash.Hash, seed []byte) {
	var counter [4]byte
	var digest []byte

	done := 0
	for done < len(out) {
		hash.Write(seed)
		hash.Write(counter[0:4])
		digest = hash.Sum(digest[:0])
		hash.Reset()

		for i := 0; i < len(digest) && done < len(out); i++ {
			out[done] ^= digest[i]
			done++
		}
		incCounter(&counter)
	}
}

// ErrMessageTooLong is returned when attempting to encrypt a message which is
// too large for the size of the public key.
var ErrMessageTooLong = errors.New("crypto/rsa: message too long for RSA public key size")

func encrypt(c *safenum.Nat, pub *PublicKey, m *safenum.Nat) *safenum.Nat {
	e := new(safenum.Nat).SetUint64(uint64(pub.E))
	c.Exp(m, e, safenum.ModulusFromBytes(pub.N.Bytes()))
	return c
}

// EncryptOAEP encrypts the given message with RSA-OAEP.
//
// OAEP is parameterised by a hash function that is used as a random oracle.
// Encryption and decryption of a given message must use the same hash function
// and sha256.New() is a reasonable choice.
//
// The random parameter is used as a source of entropy to ensure that
// encrypting the same message twice doesn't result in the same ciphertext.
//
// The label parameter may contain arbitrary data that will not be encrypted,
// but which gives important context to the message. For example, if a given
// public key is used to decrypt two types of messages then distinct label
// values could be used to ensure that a ciphertext for one purpose cannot be
// used for another by an attacker. If not required it can be empty.
//
// The message must be no longer than the length of the public modulus minus
// twice the hash length, minus a further 2.
func EncryptOAEP(hash hash.Hash, random io.Reader, pub *PublicKey, msg []byte, label []byte) ([]byte, error) {
	if err := checkPub(pub); err != nil {
		return nil, err
	}
	hash.Reset()
	k := pub.Size()
	if len(msg) > k-2*hash.Size()-2 {
		return nil, ErrMessageTooLong
	}

	hash.Write(label)
	lHash := hash.Sum(nil)
	hash.Reset()

	em := make([]byte, k)
	seed := em[1 : 1+hash.Size()]
	db := em[1+hash.Size():]

	copy(db[0:hash.Size()], lHash)
	db[len(db)-len(msg)-1] = 1
	copy(db[len(db)-len(msg):], msg)

	_, err := io.ReadFull(random, seed)
	if err != nil {
		return nil, err
	}

	mgf1XOR(db, hash, seed)
	mgf1XOR(seed, hash, db)

	m := new(safenum.Nat)
	m.SetBytes(em)
	c := encrypt(new(safenum.Nat), pub, m)

	out := make([]byte, k)
	return c.FillBytes(out), nil
}

// ErrDecryption represents a failure to decrypt a message.
// It is deliberately vague to avoid adaptive attacks.
var ErrDecryption = errors.New("crypto/rsa: decryption error")

// ErrVerification represents a failure to verify a signature.
// It is deliberately vague to avoid adaptive attacks.
var ErrVerification = errors.New("crypto/rsa: verification error")

// Precompute performs some calculations that speed up private key operations
// in the future.
func (priv *PrivateKey) Precompute() {
	if priv.Precomputed.Dp != nil {
		return
	}
	one := new(safenum.Nat).SetUint64(1)

	priv.Precomputed.Dp = new(safenum.Nat).Sub(priv.Primes[0], one, priv.Primes[0].AnnouncedLen())
	priv.Precomputed.Dp.Mod(priv.D, safenum.ModulusFromNat(*priv.Precomputed.Dp))

	priv.Precomputed.Dq = new(safenum.Nat).Sub(priv.Primes[1], one, priv.Primes[1].AnnouncedLen())
	priv.Precomputed.Dq.Mod(priv.D, safenum.ModulusFromNat(*priv.Precomputed.Dq))

	priv.Precomputed.Qinv = new(safenum.Nat).ModInverse(priv.Primes[1], safenum.ModulusFromNat(*priv.Primes[0]))

	r := new(safenum.Nat).Mul(priv.Primes[0], priv.Primes[1], priv.N.BitLen())
	priv.Precomputed.CRTValues = make([]CRTValue, len(priv.Primes)-2)
	for i := 2; i < len(priv.Primes); i++ {
		prime := priv.Primes[i]
		values := &priv.Precomputed.CRTValues[i-2]

		values.Exp = new(safenum.Nat).Sub(prime, one, prime.AnnouncedLen())
		values.Exp.Mod(priv.D, safenum.ModulusFromNat(*values.Exp))

		values.R = new(safenum.Nat).SetNat(r)
		values.Coeff = new(safenum.Nat).ModInverse(r, safenum.ModulusFromNat(*prime))

		r.Mul(r, prime, priv.N.BitLen())
	}
}

// decrypt performs an RSA decryption, resulting in a plaintext integer.
func decrypt(priv *PrivateKey, c *safenum.Nat) (m *safenum.Nat, err error) {
	if c.CmpMod(priv.N) > 0 {
		err = ErrDecryption
		return
	}
	if priv.N.BitLen() == 0 {
		return nil, ErrDecryption
	}

	if priv.Precomputed.Dp == nil {
		m = new(safenum.Nat).Exp(c, priv.D, priv.N)
	} else {
		// We have the precalculated values needed for the CRT.
		primeMod0 := safenum.ModulusFromNat(*priv.Primes[0])
		primeMod1 := safenum.ModulusFromNat(*priv.Primes[1])
		m = new(safenum.Nat).Exp(c, priv.Precomputed.Dp, primeMod0)
		m2 := new(safenum.Nat).Exp(c, priv.Precomputed.Dq, primeMod1)
		m.ModSub(m, m2, primeMod0)
		m.ModMul(m, priv.Precomputed.Qinv, primeMod0)
		m.Mul(m, priv.Primes[1], priv.N.BitLen())
		m.Add(m, m2, priv.N.BitLen())

		for i, values := range priv.Precomputed.CRTValues {
			prime := priv.Primes[2+i]
			primeMod := safenum.ModulusFromNat(*prime)

			m2.Exp(c, values.Exp, primeMod)
			m2.ModSub(m2, m, primeMod)
			m2.ModMul(m2, values.Coeff, primeMod)
			m2.Mul(m2, values.R, priv.N.BitLen())
			m.Add(m, m2, priv.N.BitLen())
		}
	}

	return
}

func decryptAndCheck(priv *PrivateKey, c *safenum.Nat) (m *safenum.Nat, err error) {
	m, err = decrypt(priv, c)
	if err != nil {
		return nil, err
	}

	// In order to defend against errors in the CRT computation, m^e is
	// calculated, which should match the original ciphertext.
	mNat := new(safenum.Nat).SetBytes(m.Bytes())
	check := new(safenum.Nat).SetBytes(encrypt(new(safenum.Nat), &priv.PublicKey, mNat).Bytes())
	if c.Cmp(check) != 0 {
		return nil, errors.New("rsa: internal error")
	}
	return m, nil
}

// DecryptOAEP decrypts ciphertext using RSA-OAEP.
//
// OAEP is parameterised by a hash function that is used as a random oracle.
// Encryption and decryption of a given message must use the same hash function
// and sha256.New() is a reasonable choice.
//
// The random parameter, if not nil, is used to blind the private-key operation
// and avoid timing side-channel attacks. Blinding is purely internal to this
// function – the random data need not match that used when encrypting.
//
// The label parameter must match the value given when encrypting. See
// EncryptOAEP for details.
func DecryptOAEP(hash hash.Hash, priv *PrivateKey, ciphertext []byte, label []byte) ([]byte, error) {
	if err := checkPub(&priv.PublicKey); err != nil {
		return nil, err
	}
	k := priv.Size()
	if len(ciphertext) > k ||
		k < hash.Size()*2+2 {
		return nil, ErrDecryption
	}

	c := new(safenum.Nat).SetBytes(ciphertext)

	m, err := decrypt(priv, c)
	if err != nil {
		return nil, err
	}

	hash.Write(label)
	lHash := hash.Sum(nil)
	hash.Reset()

	em := m.FillBytes(make([]byte, k))

	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)

	seed := em[1 : hash.Size()+1]
	db := em[hash.Size()+1:]

	mgf1XOR(seed, hash, db)
	mgf1XOR(db, hash, seed)

	lHash2 := db[0:hash.Size()]

	// We have to validate the plaintext in constant time in order to avoid
	// attacks like: J. Manger. A Chosen Ciphertext Attack on RSA Optimal
	// Asymmetric Encryption Padding (OAEP) as Standardized in PKCS #1
	// v2.0. In J. Kilian, editor, Advances in Cryptology.
	lHash2Good := subtle.ConstantTimeCompare(lHash, lHash2)

	// The remainder of the plaintext must be zero or more 0x00, followed
	// by 0x01, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the 0x01
	//   index: the offset of the first 0x01 byte
	//   invalid: 1 iff we saw a non-zero byte before the 0x01.
	var lookingForIndex, index, invalid int
	lookingForIndex = 1
	rest := db[hash.Size():]

	for i := 0; i < len(rest); i++ {
		equals0 := subtle.ConstantTimeByteEq(rest[i], 0)
		equals1 := subtle.ConstantTimeByteEq(rest[i], 1)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals1, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals1, 0, lookingForIndex)
		invalid = subtle.ConstantTimeSelect(lookingForIndex&^equals0, 1, invalid)
	}

	if firstByteIsZero&lHash2Good&^invalid&^lookingForIndex != 1 {
		return nil, ErrDecryption
	}

	return rest[index+1:], nil
}
