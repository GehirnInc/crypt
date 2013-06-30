// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package apr1_crypt implements the standard Unix MD5-crypt algorithm created
// by Poul-Henning Kamp for FreeBSD, and modified by the Apache project.
//
// The only change from MD5-crypt is the use of the magic constant "$apr1$"
// instead of "$1$". The algorithms are otherwise identical.
package apr1_crypt

import (
	"github.com/kless/crypt"
	"github.com/kless/crypt/md5_crypt"
)

var Salt = md5_crypt.Salt

func init() {
	Salt.MagicPrefix = []byte("$apr1$")
}

// Generate performs the MD5-crypt hashing algorithm, returning a full hash
// string suitable for storage and later password verification.
//
// If the salt is empty, a randomly-generated salt will be generated of length
// SaltLenMax.
func Generate(key, salt []byte) (string, error) { return md5_crypt.Generate(key, salt) }

// Verify compares a key using the same salt parameter as the given in the hash
// string.
// Returns nil on success, or an error on failure; if the hashed key is diffrent,
// the error is "crypt.ErrVerification".
func Verify(hash string, key []byte) error {
	newHash, err := Generate(key, []byte(hash))
	if err != nil {
		return err
	}
	if newHash != hash {
		return crypt.ErrVerification
	}
	return nil
}
