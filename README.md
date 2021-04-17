# ctcrypto

This is an attempt to port some of Go's standard cryptography to use
the [safenum](https://github.com/cronokirby/safenum) library. That library
provides an alternative to Go's `big.Int` type, attempting to operate without
timing leaks. This makes it more suitable for cryptography compared to `big.Int`,
which is unfortunately used pervasively throughout Go's standard cryptography routines.

The code in this repository is based on Go's standard `crypto` package, trying
to make minimal changes to use `safenum.Nat` instead of `big.Int`. This isn't
an attempt to make a useable cryptography library, but rather to see how useable
`safenum.Nat`'s API would be for replacing `big.Int`, and producing benchmarks
to see how much this switch to constant-time operation impacts real-world workloads.

*This is experimental software, use at your own peril*.
(Really, this library isn't intended for consumption, unlike `safenum`)

# Licensing

[LICENSE](LICENSE) contains an MIT license, which applies to files not originating
from Go's standard library.

For files coming from Go's standard library, [LICENSE_go](LICENSE_go) applies, as indicated
in those files' headers.
