# adbffb7fa56c1449faebd3dffecd2fb4f12e097e (2021-04-26)

```
[ctcrypto] → go test -bench=. ./rsa                                                                                                                      

goos: linux
goarch: amd64
pkg: github.com/cronokirby/ctcrypto/rsa
cpu: Intel(R) Core(TM) i5-4690K CPU @ 3.50GHz
BenchmarkRSA2048Decrypt-4                    211           5572925 ns/op
BenchmarkRSA2048Sign-4                       194           6107621 ns/op
Benchmark3PrimeRSA2048Decrypt-4              410           2872331 ns/op
PASS
ok      github.com/cronokirby/ctcrypto/rsa      5.430s

goos: linux
goarch: amd64
pkg: github.com/cronokirby/ctcrypto/rsa
cpu: Intel(R) Core(TM) i5-4690K CPU @ 3.50GHz
BenchmarkRSA2048Decrypt-4                    706           1659952 ns/op
BenchmarkRSA2048Sign-4                       693           1723803 ns/op
Benchmark3PrimeRSA2048Decrypt-4             1210            942818 ns/op
PASS
ok      github.com/cronokirby/ctcrypto/rsa      4.266s
```
# original

```
goos: linux
goarch: amd64
pkg: github.com/cronokirby/ctcrypto/elliptic
cpu: Intel(R) Core(TM) i5-4690K CPU @ 3.50GHz
BenchmarkBaseMult-4                 6196            190324 ns/op             224 B/op          5 allocs/op
BenchmarkBaseMultP256-4           244406              4275 ns/op             288 B/op          6 allocs/op
BenchmarkScalarMultP256-4          67227             17568 ns/op             256 B/op          5 allocs/op
PASS
ok      github.com/cronokirby/ctcrypto/elliptic 6.875s
```