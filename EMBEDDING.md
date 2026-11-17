# Embedded cntlm

This branch starts from `versat/cntlm` master commit
`678d30b8ab4b0b2e3fb89a43bbeedd42d385e5f7` (checked 2026-11-17, version 0.94.1).
Changes are committed here so consumers can pin this fork as a normal Git
submodule; no build-time source copy or patch application is required.

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
cached connections must all refer to that same buffered TLS stream. Direct
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
