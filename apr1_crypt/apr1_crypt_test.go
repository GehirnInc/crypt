// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package apr1_crypt

import "testing"

type testData struct {
	salt, key, result string
}

func TestCrypt(t *testing.T) {
	data := []testData{
		{
			"$apr1$$", "abcdefghijk",
			"$apr1$$NTjzQjNZnhYRPxN6ryN191",
		},
		{
			"$apr1$an overlong salt$", "abcdefgh",
			"$apr1$an overl$iroRZrWCEoQojCkf6p8LC0",
		},
		{
			"$apr1$12345678$", "Lorem ipsum dolor sit amet",
			"$apr1$12345678$/DpfgRGBHG8N0cbkmw0Fk/",
		},
		{
			"$apr1$deadbeef$", "password",
			"$apr1$deadbeef$NWLhx1Ai4ScyoaAboTFco.",
		},
		{
			"$apr1$$", "missing salt",
			"$apr1$$EcorjwkoQz4mYcksVEk6j0",
		},
		{
			"$apr1$holy-moly-batman$", "1234567",
			"$apr1$holy-mol$/WX0350ZUEkvQkrrVJsrU.",
		},
		{
			"$apr1$asdfjkl;$", "A really long password. " +
				"Longer than a password has any righ" +
				"t to be. Hey bub, don't mess with t" +
				"his password.",
			"$apr1$asdfjkl;$2MbDUb/Bj6qcIIf38PXzp0",
		},
	}
	for i, d := range data {
		hash := Crypt(d.key, d.salt)
		if hash != d.result {
			t.Errorf("Test %d failed\nExpected: %s\n     Saw: %s",
				i, d.result, hash)
		}
	}
}

func TestVerify(t *testing.T) {
	data := []string{
		"password",
		"12345",
		"That's amazing! I've got the same combination on my luggage!",
		"And change the combination on my luggage!",
		"         random  spa  c    ing.",
		"94ajflkvjzpe8u3&*j1k513KLJ&*()",
	}
	for i, d := range data {
		hash := Crypt(d, "")
		if !Verify(d, hash) {
			t.Errorf("Test %d failed: %s", i, d)
		}
	}
}

func TestGenerateSalt(t *testing.T) {
	salt := GenerateSalt(0)
	if len(salt) != len(MagicPrefix)+1 {
		t.Errorf("Expected len 1, saw len %d", len(salt))
	}

	for i := 1; i <= 8; i++ {
		salt = GenerateSalt(i)
		if len(salt) != len(MagicPrefix)+i {
			t.Errorf("Expected len %d, saw len %d", i, len(salt))
		}
	}

	salt = GenerateSalt(9)
	if len(salt) != len(MagicPrefix)+8 {
		t.Errorf("Expected len 8, saw len %d", len(salt))
	}
}
