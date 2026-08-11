# Core module boundary

Candy Cloud must not check out, compile, or vendor the private Candy Core
repository. Core is delivered as a signed, versioned native module, not as a
user-facing executable.

## Runtime layout

```text
/opt/candy/cores/<version>/libcandy_core_cloud.so
/opt/candy/cores/<version>/manifest.json
/opt/candy/cores/<version>/manifest.sig
```

`cloud-auth` and `cloud-worker` remain the only Cloud service executables. They
load an explicitly versioned module during process startup and keep that module
pinned for the lifetime of the process. A Core upgrade is activated by starting
a replacement process with a new immutable version path, completing readiness
checks, and only then retiring the old process. A loaded shared object is never
replaced in place.

## Trust boundary

Before loading the module, the Cloud host must verify:

1. the release catalog signature;
2. the bundle SHA-256 and signed Core manifest;
3. the module SHA-256 recorded by the manifest;
4. the target OS, architecture, libc, Core ABI and control API versions;
5. ownership and permissions of every directory and file in the resolved path.

The loader must resolve every symlink before verification and load the exact
verified inode. It must reject writable-by-group or writable-by-other paths,
unknown manifest fields, incompatible ABI versions and files outside the
owned Core directory.

## ABI rules

The module exposes a narrow C ABI. Rust types, allocators, panics and unwinding
must not cross that boundary. Requests and responses use length-delimited
buffers with explicit size limits. Cloud owns all buffers and uses a two-stage
size query followed by a bounded write; no allocator ownership crosses the ABI.
Every exported function catches panics and returns a stable numeric error code
plus bounded diagnostic detail.

The required v1 operations are `capabilities`, `canonicalize`, `prepare`,
`assemble`, `route-content-hash`, and `validate`. The route hash operation is
the only way Cloud obtains Core-computed route content hashes; Cloud must not
reimplement those algorithms.

Cloud owns tenant authorization, persistence, scheduling, signing-key storage
and the signing operation itself. Core owns canonical Candy protocol encoding,
signature-domain construction, signed-envelope assembly and protocol
validation. Private signing key bytes never cross the module ABI. The module
returns the exact bounded signing transcript, Cloud signs it inside its own key
boundary, and the module accepts only the resulting public signature when it
assembles and validates the envelope.

The Core artifact is a native shared module. It has no `main` function, CLI,
listener, service unit or standalone lifecycle, and it must never be installed
as `/usr/local/bin/candy-core`. Only Candy service processes load it.

## Failure behavior

Failure to load, verify or call Core prevents grant issuance and route
publication. Read-only Cloud APIs may remain available, but the affected
capability reports `unavailable`; Cloud must never synthesize a successful
generation. The previous verified module remains installed for rollback.

## Delivery

Cloud images consume a pinned Core module bundle from the signed
`candy-release` catalog. The image derives the only permitted download URL from
the pinned version and target; operators cannot inject an alternate artifact
host. CI and production builds must not use a Git checkout of
`reTsubasa/candy-core`. Unit tests use a test module implementing the same ABI;
interoperability tests use a released, signed Core module.

Starting with Core `0.3.11`, the Cloud ABI is an `abi_profiles` artifact in the
same immutable `core-v<version>` release as the full Runtime targets. SD-WAN and
Cloud integration do not create a separate Core edition or version line. The
historical `core-cloud-module-v0.3.10` release remains readable only for the
already-published compatibility pin.
