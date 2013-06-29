// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sha512_crypt implements Ulrich Drepper's SHA512-Crypt password
// hashing algorithm.
//
// The specification for this algorithm can be found here:
// http://www.akkadia.org/drepper/SHA-crypt.txt
package sha512_crypt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"strconv"

	"github.com/kless/crypt/common"
)

const (
	MagicPrefix   = "$6$"
	RoundsDefault = 5000
	RoundsMax     = 999999999
	RoundsMin     = 1000
	SaltLenMax    = 16
	SaltLenMin    = 1
)

var (
	_MagicPrefix = []byte(MagicPrefix)
	_rounds      = []byte("rounds=")
)

// GenerateSalt creates a random salt with the random bytes being of the length
// provided, and the rounds parameter set as specified.
//
// The parameters are set thus:
//
//   length > SaltLenMax: length = SaltLenMax
//   length < SaltLenMin: length = SaltLenMin
//
//   rounds < 0: rounds = RoundsDefault
//   rounds < RoundsMin: rounds = RoundsMin
//   rounds > RoundsMax: rounds = RoundsMax
//
// If rounds is equal to RoundsDefault, then the "rounds=" part of the salt is
// removed.
func GenerateSalt(length, rounds int) []byte {
	if length > SaltLenMax {
		length = SaltLenMax
	} else if length < SaltLenMin {
		length = SaltLenMin
	}
	if rounds < 0 {
		rounds = RoundsDefault
	} else if rounds < RoundsMin {
		rounds = RoundsMin
	} else if rounds > RoundsMax {
		rounds = RoundsMax
	}

	saltLen := (length * 6 / 8)
	if (length*6)%8 != 0 {
		saltLen += 1
	}
	salt := make([]byte, saltLen)
	rand.Read(salt)

	roundsText := ""
	if rounds != RoundsDefault {
		roundsText = "rounds=" + strconv.Itoa(rounds)
	}

	out := make([]byte, len(_MagicPrefix)+len(roundsText)+length)
	copy(out, _MagicPrefix)
	copy(out[len(_MagicPrefix):], []byte(roundsText))
	copy(out[len(_MagicPrefix)+len(roundsText):], common.Base64_24Bit(salt))
	return out
}

// Crypt performs the SHA512-crypt hashing algorithm, returning a full hash
// string suitable for storage and later password verification.
//
// If the salt is empty, a randomly-generated salt will be generated with a
// length of SaltLenMax and RoundsDefault number of rounds.
func Crypt(key, salt []byte) (string, error) {
	var rounds int
	var isRoundsDef bool

	if len(salt) == 0 {
		salt = GenerateSalt(SaltLenMax, RoundsDefault)
	}
	if !bytes.HasPrefix(salt, _MagicPrefix) {
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
		if rounds < RoundsMin {
			rounds = RoundsMin
		} else if rounds > RoundsMax {
			rounds = RoundsMax
		}
		salt = saltToks[3]
	} else {
		rounds = RoundsDefault
		salt = saltToks[2]
	}

	if len(salt) > 16 {
		salt = salt[0:16]
	}

	B := sha512.New()
	B.Write(key)
	B.Write(salt)
	B.Write(key)
	Bsum := B.Sum(nil)

	A := sha512.New()
	A.Write(key)
	A.Write(salt)
	i := len(key)
	for ; i > 64; i -= 64 {
		A.Write(Bsum)
	}
	A.Write(Bsum[0:i])
	for i = len(key); i > 0; i >>= 1 {
		if (i & 1) != 0 {
			A.Write(Bsum)
		} else {
			A.Write(key)
		}
	}
	Asum := A.Sum(nil)

	P := sha512.New()
	for i = 0; i < len(key); i++ {
		P.Write(key)
	}
	Psum := P.Sum(nil)

	Pseq := make([]byte, 0, len(key))
	for i = len(key); i > 64; i -= 64 {
		Pseq = append(Pseq, Psum...)
	}
	Pseq = append(Pseq, Psum[0:i]...)

	S := sha512.New()
	for i = 0; i < (16 + int(Asum[0])); i++ {
		S.Write(salt)
	}
	Ssum := S.Sum(nil)

	Sseq := make([]byte, 0, len(salt))
	for i = len(salt); i > 64; i -= 64 {
		Sseq = append(Sseq, Ssum...)
	}
	Sseq = append(Sseq, Ssum[0:i]...)

	Csum := Asum
	for i = 0; i < rounds; i++ {
		C := sha512.New()

		if (i & 1) != 0 {
			C.Write(Pseq)
		} else {
			C.Write(Csum)
		}

		if (i % 3) != 0 {
			C.Write(Sseq)
		}

		if (i % 7) != 0 {
			C.Write(Pseq)
		}

		if (i & 1) != 0 {
			C.Write(Csum)
		} else {
			C.Write(Pseq)
		}

		Csum = C.Sum(nil)
	}

	out := make([]byte, 0, 123)
	out = append(out, _MagicPrefix...)
	if isRoundsDef {
		out = append(out, []byte("rounds="+strconv.Itoa(rounds)+"$")...)
	}
	out = append(out, salt...)
	out = append(out, '$')
	out = append(out, common.Base64_24Bit([]byte{
		Csum[42], Csum[21], Csum[0],
		Csum[1], Csum[43], Csum[22],
		Csum[23], Csum[2], Csum[44],
		Csum[45], Csum[24], Csum[3],
		Csum[4], Csum[46], Csum[25],
		Csum[26], Csum[5], Csum[47],
		Csum[48], Csum[27], Csum[6],
		Csum[7], Csum[49], Csum[28],
		Csum[29], Csum[8], Csum[50],
		Csum[51], Csum[30], Csum[9],
		Csum[10], Csum[52], Csum[31],
		Csum[32], Csum[11], Csum[53],
		Csum[54], Csum[33], Csum[12],
		Csum[13], Csum[55], Csum[34],
		Csum[35], Csum[14], Csum[56],
		Csum[57], Csum[36], Csum[15],
		Csum[16], Csum[58], Csum[37],
		Csum[38], Csum[17], Csum[59],
		Csum[60], Csum[39], Csum[18],
		Csum[19], Csum[61], Csum[40],
		Csum[41], Csum[20], Csum[62],
		Csum[63],
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
