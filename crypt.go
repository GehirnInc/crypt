// (C) Copyright 2013, Jonas mg. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

// Package crypt provides interfaces for password hash functions.
package crypt

import (
	"errors"

	"github.com/kless/crypt/common"
)

var ErrKeyMismatch = errors.New("hashed password is not the hash of the given password")

// Crypter is the common interface implemented by all crypt functions.
type Crypter interface {
	// Generate performs the hashing algorithm, returning a full hash suitable
	// for storage and later password verification.
	//
	// If the salt is empty, a randomly-generated salt will be generated with a
	// length of SaltLenMax and number RoundsDefault of rounds.
	//
	// Any error only can be got when the salt argument is not empty.
	Generate(key, salt []byte) (string, error)

	// Verify compares a hashed key with its possible key equivalent.
	// Returns nil on success, or an error on failure; if the hashed key is
	// diffrent, the error is "ErrKeyMismatch".
	Verify(hashedKey string, key []byte) error

	// Cost returns the hashing cost (in rounds) used to create the given hashed
	// key.
	//
	// When, in the future, the hashing cost of a key needs to be increased in
	// order to adjust for greater computational power, this function allows one
	// to establish which keys need to be updated.
	//
	// The algorithms based in MD5-crypt use a fixed value of rounds.
	Cost(hashedKey string) (int, error)

	// SetSalt sets a different salt. It is used to easily create derivated
	// algorithms, i.e. "apr1_crypt" from "md5_crypt".
	SetSalt(salt *common.Salt)
}
