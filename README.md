pwhash - A password hashing library for Go
==========================================

The goal of pwhash is to bring a library of many common and popular password
hashing algorithms to Go and to provide a simple and consistent interface to
each of them. As every hashing method is implemented in pure Go, this library
should be as portable as Go itself.

All hashing methods come with a test suite which verifies their operation
against itself as well as the output of other password hashing implementations
to ensure compatibility with them.

To install pwhash, use the `go get` command.

    go get github.com/kless/crypt

I hope you find this library to be useful and easy to use!
