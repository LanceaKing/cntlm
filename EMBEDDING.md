# Embedded cntlm

The upstream stable baseline is `versat/cntlm` 0.94.1, tag commit
`8612658b0bd1facae7dfe6362e35649eb19992f8`. The fork starts from upstream
master `678d30b8ab4b0b2e3fb89a43bbeedd42d385e5f7`; its only differences from
that release are upstream CI updates (checked 2026-11-19).
It is maintained in `LanceaKing/cntlm` on `feat/redsocks-embedded`; ProxyDroid
pins it as the `cpp/cntlm` Git submodule. See `VENDOR.json` for the historical
import revision. No build-time source copy or
patch application is required.

`add_subdirectory(cntlm)` provides the PIC `cntlm-embedded` object target. The
host supplies the callbacks declared in `embedded.h`, initializes cntlm's
configuration/global context, owns listeners and worker lifetimes, and waits
for all workers before releasing that context. One context is supported at a
time. The embedded target excludes the executable entry point, process signal
registration, daemonization, and the standalone worker bookkeeping. Fatal
errors return control through the host's failure callback instead of exiting
the hosting process. The standalone `./configure && make` build is retained.

The transport callback receives the parent's DNS name as well as its resolved
IPv4/IPv6 addresses. A TLS host must verify the peer and complete the handshake
before returning the connected stream. Read/write, readiness, half-close, and
cached connections must all refer to that same buffered TLS stream. cntlm
does not select or bundle a TLS library; the host uses libevent's selected
native backend for every parent connection. Direct
NoProxy connections pass a null proxy name. Authentication has a bounded idle
timeout supplied by the host.

The fork also validates NTLM Type2 security buffers/AV pairs, restarts the
handshake after a closed 407, uses bodyless OPTIONS probes for HTTP requests,
avoids replaying a submitted request after cached authentication fails, reads
fragmented SOCKS5 fields fully, resets parent/cache state, and protects PAC
evaluation and returned-string ownership. DES byte decoding uses unsigned
32-bit shifts and is covered by an encryption/decryption vector. Configuration
accepts escaped quoted values and a final line without a newline. The portable target supports NTLM
dialects; GSS/Kerberos and Windows SSPI remain platform-specific standalone
features.

Run the focused core regressions independently of a host:

```sh
cmake -S . -B /tmp/cntlm-build -DCNTLM_BUILD_TESTS=ON
cmake --build /tmp/cntlm-build -j4
ctest --test-dir /tmp/cntlm-build --output-on-failure
```

The redsocks consumer additionally tests actual plaintext/TLS HTTP, CONNECT,
SOCKS5, authentication, forwarding, and repeated engine start/stop behavior.

Retained patches are limited to the embedding callbacks/lifecycle, target libc
and minimum Android API support, and the failure cases above. Core test
functions are the evidence for DES, Type2 bounds/unaligned input,
configuration/descriptor ownership, parent reset and PAC errors/empty storage.
Consumer protocol tests cover closed-407 restart, POST non-replay, fragmented
SOCKS5, cached streams and TLS verification. Changes to protocol code need a
concrete failing case; prefer an upstream release or fix before adding a patch.
