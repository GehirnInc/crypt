// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sha256_crypt implements Ulrich Drepper's SHA256-crypt password
// hashing algorithm.
//
// The specification for this algorithm can be found here:
// http://www.akkadia.org/drepper/SHA-crypt.txt
package sha256_crypt

import (
	"bytes"
	"crypto/sha256"
	"strconv"

	"github.com/kless/crypt/common"
)

var Salt = &common.Salt{
	MagicPrefix:   []byte("$5$"),
	SaltLenMin:    1,
	SaltLenMax:    16,
	RoundsMin:     1000,
	RoundsMax:     999999999,
	RoundsDefault: 5000,
}

var _rounds = []byte("rounds=")

// Generate performs the SHA256-crypt hashing algorithm, returning a full hash
// suitable for storage and later password verification.
//
// If the salt is empty, a randomly-generated salt will be generated with a
// length of SaltLenMax and RoundsDefault number of rounds.
func Generate(key, salt []byte) (string, error) {
	var rounds int
	var isRoundsDef bool

	if len(salt) == 0 {
		salt = Salt.GenerateWRounds(Salt.SaltLenMax, Salt.RoundsDefault)
	}
	if !bytes.HasPrefix(salt, Salt.MagicPrefix) {
		return "", common.ErrSaltPrefix
	}

	saltToks := bytes.Split(salt, []byte{'$'})

	if len(saltToks) < 3 {
		return "", common.ErrSaltFormat
	}

	if bytes.HasPrefix(saltToks[2], _rounds) {
		isRoundsDef = true
		pr, err := strconv.ParseInt(string(saltToks[2][7:]), 10, 32)
		if err != nil {
			return "", common.ErrSaltRounds
		}
		rounds = int(pr)
		if rounds < Salt.RoundsMin {
			rounds = Salt.RoundsMin
		} else if rounds > Salt.RoundsMax {
			rounds = Salt.RoundsMax
		}
		salt = saltToks[3]
	} else {
		rounds = Salt.RoundsDefault
		salt = saltToks[2]
	}

	if len(salt) > 16 {
		salt = salt[0:16]
	}

	// Compute alternate SHA256 sum with input KEY, SALT, and KEY.
	Alternate := sha256.New()
	Alternate.Write(key)
	Alternate.Write(salt)
	Alternate.Write(key)
	AlternateSum := Alternate.Sum(nil) // 32 bytes

	A := sha256.New()
	A.Write(key)
	A.Write(salt)
	// Add for any character in the key one byte of the alternate sum.
	i := len(key)
	for ; i > 32; i -= 32 {
		A.Write(AlternateSum)
	}
	A.Write(AlternateSum[0:i])

	// Take the binary representation of the length of the key and for every add
	// the alternate sum, for every 0 the key.
	for i = len(key); i > 0; i >>= 1 {
		if (i & 1) != 0 {
			A.Write(AlternateSum)
		} else {
			A.Write(key)
		}
	}
	Asum := A.Sum(nil)

	// Start computation of P byte sequence.
	P := sha256.New()
	// For every character in the password add the entire password.
	for i = 0; i < len(key); i++ {
		P.Write(key)
	}
	Psum := P.Sum(nil)
	// Create byte sequence P.
	Pseq := make([]byte, 0, len(key))
	for i = len(key); i > 32; i -= 32 {
		Pseq = append(Pseq, Psum...)
	}
	Pseq = append(Pseq, Psum[0:i]...)

	// Start computation of S byte sequence.
	S := sha256.New()
	for i = 0; i < (16 + int(Asum[0])); i++ {
		S.Write(salt)
	}
	Ssum := S.Sum(nil)
	// Create byte sequence S.
	Sseq := make([]byte, 0, len(salt))
	for i = len(salt); i > 32; i -= 32 {
		Sseq = append(Sseq, Ssum...)
	}
	Sseq = append(Sseq, Ssum[0:i]...)

	Csum := Asum

	// Clean sensitive data for security.
	go func() {
		A.Reset()
		Alternate.Reset()
		P.Reset()

		for i = 0; i < len(Asum); i++ {
			Asum[i] = 0
		}
		for i = 0; i < len(AlternateSum); i++ {
			AlternateSum[i] = 0
		}
	}()

	// Repeatedly run the collected hash value through SHA256 to burn CPU cycles.
	for i = 0; i < rounds; i++ {
		C := sha256.New()

		// Add key or last result.
		if (i & 1) != 0 {
			C.Write(Pseq)
		} else {
			C.Write(Csum)
		}
		// Add salt for numbers not divisible by 3.
		if (i % 3) != 0 {
			C.Write(Sseq)
		}
		// Add key for numbers not divisible by 7.
		if (i % 7) != 0 {
			C.Write(Pseq)
		}
		// Add key or last result.
		if (i & 1) != 0 {
			C.Write(Csum)
		} else {
			C.Write(Pseq)
		}

		Csum = C.Sum(nil)
	}

	out := make([]byte, 0, 80)
	out = append(out, Salt.MagicPrefix...)
	if isRoundsDef {
		out = append(out, []byte("rounds="+strconv.Itoa(rounds)+"$")...)
	}
	out = append(out, salt...)
	out = append(out, '$')
	out = append(out, common.Base64_24Bit([]byte{
		Csum[20], Csum[10], Csum[0],
		Csum[11], Csum[1], Csum[21],
		Csum[2], Csum[22], Csum[12],
		Csum[23], Csum[13], Csum[3],
		Csum[14], Csum[4], Csum[24],
		Csum[5], Csum[25], Csum[15],
		Csum[26], Csum[16], Csum[6],
		Csum[17], Csum[7], Csum[27],
		Csum[8], Csum[28], Csum[18],
		Csum[29], Csum[19], Csum[9],
		Csum[30], Csum[31],
	})...)

	// Clean sensitive data.
	for i = 0; i < len(Pseq); i++ {
		Pseq[i] = 0
	}
	for i = 0; i < len(Csum); i++ {
		Csum[i] = 0
	}

	return string(out), nil
}

// Verify hashes a key using the same salt parameter as the given in the hash,
// and if the results match, it returns true.
func Verify(key []byte, hash string) bool {
	newHash, err := Generate(key, []byte(hash))
	if err != nil {
		return false
	}
	return newHash == hash
}
