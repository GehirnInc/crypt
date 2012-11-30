// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha256_crypt

import "testing"

func TestCrypt(t *testing.T) {
	data := [][]string{
		{
			"$5$saltstring",
			"Hello world!",
			"$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/G" +
				"NooZaBBGWEc5",
		},
		{
			"$5$rounds=10000$saltstringsaltstring",
			"Hello world!",
			"$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41" +
				"AL9AvLeujZkZRBAwqFMz2.opqey6IcA",
		},
		{
			"$5$rounds=5000$toolongsaltstring",
			"This is just a test",
			"$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ" +
				"5.mWJpuVolil07guHPvOW8mGRcvxa5",
		},
		{
			"$5$rounds=1400$anotherlongsaltstring",
			"a very much longer text to encrypt.  " +
				"This one even stretches over more" +
				"than one line.",
			"$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjED" +
				"GomFU8bDkXm3XIUnzyxf12oP84Bnq1",
		},
		{
			"$5$rounds=77777$short",
			"we have a short salt string but not a short password",
			"$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEF" +
				"ysAe1mZNJRs3pw0KQRd/",
		},
		{
			"$5$rounds=123456$asaltof16chars..",
			"a short string",
			"$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UU" +
				"EW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD",
		},
		{
			"$5$rounds=10$roundstoolow",
			"the minimum number is still observed",
			"$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWy" +
				"uPMDNHpIVlTQebY9l/gL972bIC",
		},
	}

	for i, d := range data {
		hash := Crypt(d[1], d[0])
		if hash != d[2] {
			t.Errorf("Test %d failed\nExpected: %s\n     Saw: %s",
				i, d[2], hash)
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
