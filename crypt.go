// (C) Copyright 2013, Jonas mg <jonas.mg@sent.at>. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

// Package crypt implements many common password hashing algorithms.
package crypt

import "errors"

var ErrVerification = errors.New("hashed password is not the hash of the given password")

// Crypter is the common interface implemented by all crypt functions.
type Crypter interface {
	// Generate performs the crypt hashing of the key with an optional salt.
	Generate(key, salt []byte) (string, error)

	// Verify compares a hashed key with its possible plaintext equivalent.
	// Returns nil on success, or an error on failure; if the hashed key is
	// diffrent, the error is "ErrVerification".
	Verify(hash string, key []byte) error
}
