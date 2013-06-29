// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package md5_crypt

import "testing"

func TestCrypt(t *testing.T) {
	data := []struct {
		salt []byte
		key  []byte
		out  string
	}{
		{
			[]byte("$1$$"),
			[]byte("abcdefghijk"),
			"$1$$pL/BYSxMXs.jVuSV1lynn1",
		},
		{
			[]byte("$1$an overlong salt$"),
			[]byte("abcdfgh"),
			"$1$an overl$ZYftmJDIw8sG5s4gG6r.70",
		},
		{
			[]byte("$1$12345678$"),
			[]byte("Lorem ipsum dolor sit amet"),
			"$1$12345678$Suzx8CrBlkNJwVHHHv5tZ.",
		},
		{
			[]byte("$1$deadbeef$"),
			[]byte("password"),
			"$1$deadbeef$Q7g0UO4hRC0mgQUQ/qkjZ0",
		},
		{
			[]byte("$1$$"),
			[]byte("missing salt"),
			"$1$$Lv61fbMiEGprscPkdE9Iw/",
		},
		{
			[]byte("$1$holy-moly-batman$"),
			[]byte("1234567"),
			"$1$holy-mol$WKomB0dWknSxdW/e8WYHG0",
		},
		{
			[]byte("$1$asdfjkl;$"),
			[]byte("A really long password. Longer " +
				"than a password has any right to be" +
				". Hey bub, don't mess with this password."),
			"$1$asdfjkl;$DUqPhKwbK4smV0aEMyDdx/",
		},
	}

	for i, d := range data {
		hash := Crypt(d.key, d.salt)
		if hash != d.out {
			t.Errorf("Test %d failed\nExpected: %s\n     Saw: %s",
				i, d.out, hash)
		}
	}
}

func TestVerify(t *testing.T) {
	data := [][]byte{
		[]byte("password"),
		[]byte("12345"),
		[]byte("That's amazing! I've got the same combination on my luggage!"),
		[]byte("And change the combination on my luggage!"),
		[]byte("         random  spa  c    ing."),
		[]byte("94ajflkvjzpe8u3&*j1k513KLJ&*()"),
	}
	for i, d := range data {
		hash := Crypt(d, nil)
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
