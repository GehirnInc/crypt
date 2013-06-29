// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package md5_crypt implements the standard Unix MD5-crypt algorithm created by
// Poul-Henning Kamp for FreeBSD.
package md5_crypt

import (
	"bytes"
	"crypto/md5"

	"github.com/kless/crypt/common"
)

// NOTE: Cisco IOS only allows salts of length 4.

var Salt = &common.Salt{
	MagicPrefix: []byte("$1$"),
	SaltLenMin:  1, // Real minimum is 0, but that isn't useful.
	SaltLenMax:  8,
}

// Generate performs the MD5-crypt hashing algorithm, returning a full hash
// suitable for storage and later password verification.
//
// If the salt is empty, a randomly-generated salt will be generated of length
// SaltLenMax.
func Generate(key, salt []byte) (string, error) {
	if len(salt) == 0 {
		salt = Salt.Generate(Salt.SaltLenMax)
	}
	if !bytes.HasPrefix(salt, Salt.MagicPrefix) {
		return "", common.ErrSaltPrefix
	}

	saltToks := bytes.Split(salt, []byte{'$'})

	if len(saltToks) < 3 {
		return "", common.ErrSaltFormat
	} else {
		salt = saltToks[2]
	}

	if len(salt) > 8 {
		salt = salt[0:8]
	}

	// Compute alternate MD5 sum with input KEY, SALT, and KEY.
	Alternate := md5.New()
	Alternate.Write(key)
	Alternate.Write(salt)
	Alternate.Write(key)
	AlternateSum := Alternate.Sum(nil) // 16 bytes

	A := md5.New()
	A.Write(key)
	A.Write(Salt.MagicPrefix)
	A.Write(salt)
	// Add for any character in the key one byte of the alternate sum.
	i := len(key)
	for ; i > 16; i -= 16 {
		A.Write(AlternateSum)
	}
	A.Write(AlternateSum[0:i])

	// The original implementation now does something weird:
	//   For every 1 bit in the key, the first 0 is added to the buffer
	//   For every 0 bit, the first character of the key
	// This does not seem to be what was intended but we have to follow this to
	// be compatible.
	for i = len(key); i > 0; i >>= 1 {
		if (i & 1) == 0 {
			A.Write(key[0:1])
		} else {
			A.Write([]byte{0})
		}
	}
	Csum := A.Sum(nil)

	// In fear of password crackers here comes a quite long loop which just
	// processes the output of the previous round again.
	// We cannot ignore this here.
	for i = 0; i < 1000; i++ {
		C := md5.New()

		// Add key or last result.
		if (i & 1) != 0 {
			C.Write(key)
		} else {
			C.Write(Csum)
		}
		// Add salt for numbers not divisible by 3.
		if (i % 3) != 0 {
			C.Write(salt)
		}
		// Add key for numbers not divisible by 7.
		if (i % 7) != 0 {
			C.Write(key)
		}
		// Add key or last result.
		if (i & 1) == 0 {
			C.Write(key)
		} else {
			C.Write(Csum)
		}

		Csum = C.Sum(nil)
	}

	out := make([]byte, 0, 23+len(Salt.MagicPrefix)+len(salt))
	out = append(out, Salt.MagicPrefix...)
	out = append(out, salt...)
	out = append(out, '$')
	out = append(out, common.Base64_24Bit([]byte{
		Csum[12], Csum[6], Csum[0],
		Csum[13], Csum[7], Csum[1],
		Csum[14], Csum[8], Csum[2],
		Csum[15], Csum[9], Csum[3],
		Csum[5], Csum[10], Csum[4],
		Csum[11],
	})...)

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
