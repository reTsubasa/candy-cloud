Candy Cloud serves architecture-bound Linux installation manifests from this directory.

Release deployment must provide linux-x86_64.json and linux-aarch64.json. Each
manifest is generated from a finalized Candy Runtime Release and has this shape:

{
  "schema_version": 1,
  "platform": "linux",
  "architecture": "x86_64",
  "runtime_version": "0.4.0-r25",
  "runtime_url": "/install/artifacts/candy-server-runtime-x86_64.tar.gz",
  "runtime_sha256": "64 lowercase hexadecimal characters",
  "runtime_size": 12345678
}

Never publish a manifest before the referenced finalized asset exists. The node
installer rejects missing, oversized, cross-platform, cross-architecture, or
digest-mismatched artifacts before changing the host.
