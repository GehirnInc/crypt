// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package common

// Hash64Chars is the character set used by the Hash64 encoding algorithm.
const Hash64Chars = "./0123456789" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
	"abcdefghijklmnopqrstuvwxyz"

// Hash64 is a variant of Base64 encoding.  It is commonly used with
// password hashing algorithms to encode the result of their checksum
// output.
//
// The algorithm operates on up to 3 bytes at a time, encoding the
// following 6-bit sequences into up to 4 hash64 ASCII bytes.
//
//     1. Bottom 6 bits of the first byte
//     2. Top 2 bits of the first byte, and bottom 4 bits of the second byte.
//     3. Top 4 bits of the second byte, and bottom 2 bits of the third byte.
//     4. Top 6 bits of the third byte.
//
// This encoding method does not emit padding bytes as Base64 does.
func Hash64(src []byte) (hash []byte) {
	if len(src) == 0 {
		return []byte{}
	}

	hashSize := (len(src) * 8) / 6
	if (len(src) % 6) != 0 {
		hashSize += 1
	}
	hash = make([]byte, hashSize)

	dst := hash
	for len(src) > 0 {
		switch len(src) {
		default:
			dst[0] = Hash64Chars[src[0]&0x3f]
			dst[1] = Hash64Chars[((src[0]>>6)|(src[1]<<2))&0x3f]
			dst[2] = Hash64Chars[((src[1]>>4)|(src[2]<<4))&0x3f]
			dst[3] = Hash64Chars[(src[2]>>2)&0x3f]
			src = src[3:]
			dst = dst[4:]
		case 2:
			dst[0] = Hash64Chars[src[0]&0x3f]
			dst[1] = Hash64Chars[((src[0]>>6)|(src[1]<<2))&0x3f]
			dst[2] = Hash64Chars[(src[1]>>4)&0x3f]
			src = src[2:]
			dst = dst[3:]
		case 1:
			dst[0] = Hash64Chars[src[0]&0x3f]
			dst[1] = Hash64Chars[(src[0]>>6)&0x3f]
			src = src[1:]
			dst = dst[2:]

		}
	}

	return
}
