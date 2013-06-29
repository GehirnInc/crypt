// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha256_crypt

import "testing"

func TestGenerate(t *testing.T) {
	data := []struct {
		salt []byte
		key  []byte
		out  string
	}{
		{
			[]byte("$5$saltstring"),
			[]byte("Hello world!"),
			"$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
		},
		{
			[]byte("$5$rounds=10000$saltstringsaltstring"),
			[]byte("Hello world!"),
			"$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFM" +
				"z2.opqey6IcA",
		},
		{
			[]byte("$5$rounds=5000$toolongsaltstring"),
			[]byte("This is just a test"),
			"$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPv" +
				"OW8mGRcvxa5",
		},
		{
			[]byte("$5$rounds=1400$anotherlongsaltstring"),
			[]byte("a very much longer text to encrypt.  " +
				"This one even stretches over more" +
				"than one line."),
			"$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyx" +
				"f12oP84Bnq1",
		},
		{
			[]byte("$5$rounds=77777$short"),
			[]byte("we have a short salt string but not a short password"),
			"$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/",
		},
		{
			[]byte("$5$rounds=123456$asaltof16chars.."),
			[]byte("a short string"),
			"$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPy" +
				"zV/cZKmF/wJvD",
		},
		{
			[]byte("$5$rounds=10$roundstoolow"),
			[]byte("the minimum number is still observed"),
			"$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/g" +
				"L972bIC",
		},
	}

	for i, d := range data {
		hash, _ := Generate(d.key, d.salt)
		if hash != d.out {
			t.Errorf("Test %d failed\nExpected: %s\n     Got: %s", i, d.out, hash)
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
		hash, _ := Generate(d, nil)
		if !Verify(d, hash) {
			t.Errorf("Test %d failed: %s", i, d)
		}
	}
}
