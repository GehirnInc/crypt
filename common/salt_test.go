// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package common

import "testing"

var _Salt = &Salt{
	MagicPrefix: []byte("$foo$"),
	SaltLenMin:  1,
	SaltLenMax:  8,
}

func TestGenerateSalt(t *testing.T) {
	salt := _Salt.Generate(0)
	if len(salt) != len(_Salt.MagicPrefix)+1 {
		t.Errorf("Expected len 1, got len %d", len(salt))
	}

	for i := 1; i <= 8; i++ {
		salt = _Salt.Generate(i)
		if len(salt) != len(_Salt.MagicPrefix)+i {
			t.Errorf("Expected len %d, got len %d", i, len(salt))
		}
	}

	salt = _Salt.Generate(9)
	if len(salt) != len(_Salt.MagicPrefix)+8 {
		t.Errorf("Expected len 8, got len %d", len(salt))
	}
}
