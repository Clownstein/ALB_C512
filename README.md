# ALB_C512 research project

> **Do not use any implementation in this repository to protect real information.**
>
> C512 and its variants are withdrawn research ciphers. Their central transform
> is many-to-one, despite the historical design describing it as a permutation.
> No claim of quantum resistance, confidentiality, integrity, or production
> readiness is supported.
>
> [`albpkg/`](albpkg/README.md) is a separate, incomplete review candidate built
> from maintained cryptographic providers. It is not approved for real data;
> see its [release gate](albpkg/RELEASE_STATUS.md). It never falls back to C512.

## Project status

This repository preserves C512 source and vectors for reproducibility,
regression demonstrations, and research. The explicit environment opt-in only
controls access to the legacy test implementation. It does not make the cipher
safe. See [`SECURITY.md`](SECURITY.md) for the evidence and limits, and
[`REMEDIATION.md`](REMEDIATION.md) for the accepted containment plan.

The supported implementation effort is ALBPKG/1. At present, its C, Go,
Python, and TypeScript ports have partial interoperability coverage; four
independent ports, full platform acceptance, and independent review remain
outstanding. Local tests establish implementation consistency only, not
cryptographic security.

## Useful entry points

- [`albpkg/FORMAT.md`](albpkg/FORMAT.md): candidate wire format and security
  boundaries.
- [`albpkg/RELEASE_STATUS.md`](albpkg/RELEASE_STATUS.md): verified work and
  blocked release gates.
- [`tools/c512_structural_regressions.py`](tools/c512_structural_regressions.py):
  reproduces known C512 transform collisions.
- [`tools/migrate_c512_file.py`](tools/migrate_c512_file.py): explicit,
  source-preserving migration for the bounded legacy demo framing. This is a
  compatibility tool and does not establish security of the old data.

## Local checks

Use the test commands described in the per-port directories and run
`tools/make_release.py` only as a validation gate. The release tool refuses to
create a distributable release until all ports and independent reviews pass.
A `--skip-tests` archive is explicitly marked unvalidated and is not for
distribution. Do not interpret vectors, round trips, benchmarks, statistical
tests, or successful compilation as evidence that a cipher is secure.

The old `DESIGN.md`, `IMPLEMENTATION.md`, `AEAD_API.md`,
`DOCUMENTATION_COMPLETE.md`, and the historical sections of `CHANGELOG.md` are
archival records only; their security and usage claims are withdrawn.
