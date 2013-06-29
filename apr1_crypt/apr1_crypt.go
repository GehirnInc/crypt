// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package apr1_crypt implements the standard Unix MD5-Crypt algorithm
// created by Poul-Henning Kamp for FreeBSD, and modified by the Apache
// project.
//
// The only change from MD5-Crypt is the use of the magic constant
// "$apr1$" instead of "$1$". The algorithms are otherwise identical.
package apr1_crypt

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"

	"github.com/kless/crypt/common"
)

const (
	MagicPrefix = "$apr1$"
	RandomSalt  = ""
	SaltLenMax  = 8
	SaltLenMin  = 1 // Real minimum is 0, but that isn't useful.
)

var _MagicPrefix = []byte(MagicPrefix)

// GenerateSalt generates a random salt of a given length.
//
// The length is set thus:
//
//   length > SaltLenMax: length = SaltLenMax
//   length < SaltLenMin: length = SaltLenMin
func GenerateSalt(length int) []byte {
	if length > SaltLenMax {
		length = SaltLenMax
	} else if length < SaltLenMin {
		length = SaltLenMin
	}

	saltLen := (length * 6 / 8)
	if (length*6)%8 != 0 {
		saltLen += 1
	}
	salt := make([]byte, saltLen)
	rand.Read(salt)

	out := make([]byte, len(_MagicPrefix)+length)
	copy(out, _MagicPrefix)
	copy(out[len(_MagicPrefix):], common.Base64_24Bit(salt))
	return out
}

// Crypt takes key and salt strings and performs the MD5-Crypt hashing
// algorithm on them, returning a full hash string suitable for storage
// and later password verification.
//
// If the salt string is the value RandomSalt, a randomly-generated salt
// parameter string will be generated of length SaltLenMax.
func Crypt(key, salt []byte) string {
	if salt == nil || len(salt) == 0 {
		salt = GenerateSalt(SaltLenMax)
	}
	if !bytes.HasPrefix(salt, _MagicPrefix) {
		return "invalid magic prefix"
	}

	saltToks := bytes.Split(salt, []byte{'$'})

	if len(saltToks) < 3 {
		return "invalid salt format"
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
	A.Write(_MagicPrefix)
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

	buf := make([]byte, 0, 23+len(MagicPrefix)+len(salt))
	buf = append(buf, MagicPrefix...)
	buf = append(buf, salt...)
	buf = append(buf, '$')
	buf = append(buf, common.Base64_24Bit([]byte{
		Csum[12], Csum[6], Csum[0],
		Csum[13], Csum[7], Csum[1],
		Csum[14], Csum[8], Csum[2],
		Csum[15], Csum[9], Csum[3],
		Csum[5], Csum[10], Csum[4],
		Csum[11],
	})...)

	return string(buf)
}

// Verify hashes a key using the same salt parameters as the given
// hash string, and if the results match, it returns true.
func Verify(key []byte, hash string) bool { return Crypt(key, []byte(hash)) == hash }
