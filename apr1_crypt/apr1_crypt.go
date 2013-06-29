// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package apr1_crypt implements the standard Unix MD5-Crypt algorithm created
// by Poul-Henning Kamp for FreeBSD, and modified by the Apache project.
//
// The only change from MD5-Crypt is the use of the magic constant "$apr1$"
// instead of "$1$". The algorithms are otherwise identical.
package apr1_crypt

import (
	"bytes"
	"crypto/md5"

	"github.com/kless/crypt/common"
)

var Salt = &common.Salt{
	MagicPrefix: []byte("$apr1$"),
	SaltLenMin:  1, // Real minimum is 0, but that isn't useful.
	SaltLenMax:  8,
}

// Crypt performs the MD5-Crypt hashing algorithm, returning a full hash string
// suitable for storage and later password verification.
//
// If the salt is empty, a randomly-generated salt will be generated of length
// SaltLenMax.
func Crypt(key, salt []byte) (string, error) {
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

	B := md5.New()
	B.Write(key)
	B.Write(salt)
	B.Write(key)
	Bsum := B.Sum(nil)

	A := md5.New()
	A.Write(key)
	A.Write(Salt.MagicPrefix)
	A.Write(salt)
	i := len(key)
	for ; i > 16; i -= 16 {
		A.Write(Bsum)
	}
	A.Write(Bsum[0:i])
	for i = len(key); i > 0; i >>= 1 {
		if (i & 1) == 0 {
			A.Write(key[0:1])
		} else {
			A.Write([]byte{0})
		}
	}
	Asum := A.Sum(nil)

	Csum := Asum
	for round := 0; round < 1000; round++ {
		C := md5.New()

		if (round & 1) != 0 {
			C.Write(key)
		} else {
			C.Write(Csum)
		}

		if (round % 3) != 0 {
			C.Write(salt)
		}

		if (round % 7) != 0 {
			C.Write(key)
		}

		if (round & 1) == 0 {
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

// Verify hashes a key using the same salt parameter as the given in the hash
// string, and if the results match, it returns true.
func Verify(key []byte, hash string) bool {
	c, err := Crypt(key, []byte(hash))
	if err != nil {
		return false
	}
	return c == hash
}
