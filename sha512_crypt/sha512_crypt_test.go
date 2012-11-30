// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha512_crypt

import "testing"

func TestCrypt(t *testing.T) {
	data := [][]string{
		{
			"$6$saltstring",
			"Hello world!",
			"$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSM" +
				"HWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdc" +
				"bYEdFCoEOfaS35inz1",
		},
		{
			"$6$rounds=10000$saltstringsaltstring",
			"Hello world!",
			"$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6B" +
				"cXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/Urj" +
				"mM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.",
		},
		{
			"$6$rounds=5000$toolongsaltstring",
			"This is just a test",
			"$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY" +
				"4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGD" +
				"ZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0",
		},
		{
			"$6$rounds=1400$anotherlongsaltstring",
			"a very much longer text to encrypt.  " +
				"This one even stretches over more" +
				"than one line.",
			"$6$rounds=1400$anotherlongsalts$POfYwTEok97VW" +
				"cjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3" +
				"CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1",
		},
		{
			"$6$rounds=77777$short",
			"we have a short salt string but not a short password",
			"$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/if" +
				"Iw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CC" +
				"aUeOxFmtlcGZelFl5CxtgfiAc0",
		},
		{
			"$6$rounds=123456$asaltof16chars..",
			"a short string",
			"$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5" +
				"hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6" +
				"ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1",
		},
		{
			"$6$rounds=10$roundstoolow",
			"the minimum number is still observed",
			"$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.F" +
				"RkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt5" +
				"8jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.",
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
