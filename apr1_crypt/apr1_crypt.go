// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package apr1_crypt implements the standard Unix MD5-Crypt algorithm created
// by Poul-Henning Kamp for FreeBSD, and modified by the Apache project.
//
// The only change from MD5-Crypt is the use of the magic constant "$apr1$"
// instead of "$1$". The algorithms are otherwise identical.
package apr1_crypt

import "github.com/kless/crypt/md5_crypt"

var Salt = md5_crypt.Salt

func init() {
	Salt.MagicPrefix = []byte("$apr1$")
}

// Crypt performs the MD5-Crypt hashing algorithm, returning a full hash string
// suitable for storage and later password verification.
//
// If the salt is empty, a randomly-generated salt will be generated of length
// SaltLenMax.
func Crypt(key, salt []byte) (string, error) { return md5_crypt.Crypt(key, salt) }

// Verify hashes a key using the same salt parameter as the given in the hash
// string, and if the results match, it returns true.
func Verify(key []byte, hash string) bool {
	c, err := Crypt(key, []byte(hash))
	if err != nil {
		return false
	}
	return c == hash
}
