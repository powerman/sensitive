# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.2] - 2026-07-12

[0.6.2]: https://github.com/powerman/sensitive/compare/v0.6.1..v0.6.2

## [0.6.1] - 2026-07-12

### 📦️ Dependencies

- **(deps)** Update powerman/check to v1.13.0 and prune indirect deps by @powerman in [3013785]

[0.6.1]: https://github.com/powerman/sensitive/compare/v0.6.0..v0.6.1
[3013785]: https://github.com/powerman/sensitive/commit/30137859764082ab34e90f9cbbb6077f370a7e63

## [0.6.0] - 2026-07-04

### ➖ Removed

- **⚠️ BREAKING!** Remove deprecated legacy named types by @powerman in [602383c]

[0.6.0]: https://github.com/powerman/sensitive/compare/v0.5.1..v0.6.0
[602383c]: https://github.com/powerman/sensitive/commit/602383cdb586e694ba1f9f6441d6159f47e22343

## [0.5.1] - 2026-07-04

### 📚 Documentation

- Improve package docs, add method-level doc comments, fix godoc references by @powerman in [9bae2f1]
- Fix semantic linefeeds in package doc list formatting by @powerman in [2e9250a]

[0.5.1]: https://github.com/powerman/sensitive/compare/v0.5.0..v0.5.1
[9bae2f1]: https://github.com/powerman/sensitive/commit/9bae2f1019b10242c7d231af562b1b1e58c7dd9b
[2e9250a]: https://github.com/powerman/sensitive/commit/2e9250ae8a54d845a4e7417f57a91efa611bf71f

## [0.5.0] - 2026-07-04

### 🔔 Changed

- Broaden SecretValuer to expose secrets for JSON/Text serialization by @powerman in [43fe8a7]
- Make SecretValuer an inert non-embedding egress+ingress type by @powerman in [165a585]

[0.5.0]: https://github.com/powerman/sensitive/compare/v0.4.0..v0.5.0
[43fe8a7]: https://github.com/powerman/sensitive/commit/43fe8a78d1c280d40874d46efa3ef8f5c9c89000
[165a585]: https://github.com/powerman/sensitive/commit/165a585ad7afb7b1f78965bf3f45f4d6dca0fa73

## [0.4.0] - 2026-07-04

### 🚀 Added

- Add IsZero() to Ref and Handle for omitzero support by @powerman in [6546849]

[0.4.0]: https://github.com/powerman/sensitive/compare/v0.3.1..v0.4.0
[6546849]: https://github.com/powerman/sensitive/commit/654684949db3c3a84389444f145c034d293c3db4

## [0.3.1] - 2026-07-03

### 📚 Documentation

- Add protection-layer documentation to package doc by @powerman in [1e51fa8]

[0.3.1]: https://github.com/powerman/sensitive/compare/v0.3.0..v0.3.1
[1e51fa8]: https://github.com/powerman/sensitive/commit/1e51fa8116c42c257534fcb704878f39a36cfcfa

## [0.3.0] - 2026-07-02

### 🚀 Added

- Add ingest-side serialization for Ref and Handle by @powerman in [01fdb0a]
- Add in-memory encryption for string and []byte secrets by @powerman in [ef78ee2]

### 📚 Documentation

- Add comparison rows for rsjethani/secret and andrewbenton/go-secrets by @powerman in [d1cd9c3]
- Rewrite comparison table in README by @powerman in [f2c7a24]

[0.3.0]: https://github.com/powerman/sensitive/compare/v0.2.0..v0.3.0
[d1cd9c3]: https://github.com/powerman/sensitive/commit/d1cd9c3515f6b5265f632aa2590a6b50412269a0
[01fdb0a]: https://github.com/powerman/sensitive/commit/01fdb0abe2e05d35c76f4d8e9e836d74f16cd5fd
[f2c7a24]: https://github.com/powerman/sensitive/commit/f2c7a24242516f02877356077d67f6750468d948
[ef78ee2]: https://github.com/powerman/sensitive/commit/ef78ee2fe8e27ba9d39dbe5f1415274d39a470ed

## [0.2.0] - 2026-07-02

### 🚀 Added

- Add Handle[T] and Make[T] for comparable canonicalized secrets by @powerman in [26328a5]

### 🔔 Changed

- **⚠️ BREAKING!** Rename Boxed to Ref and make it non-comparable by @powerman in [0d4a2f4]

### 📚 Documentation

- Improve by @powerman in [beaa2a9]
- Explain why typed redacted values are used per type by @powerman in [572e177]
- Mark legacy plain named types as deprecated by @powerman in [e8866d2]
- Refine and restructure package documentation by @powerman in [9aefe6a]
- Rewrite README, update package doc and examples by @powerman in [f402ccd]

[0.2.0]: https://github.com/powerman/sensitive/compare/v0.0.7..v0.2.0
[0d4a2f4]: https://github.com/powerman/sensitive/commit/0d4a2f4ee334639fa9fe92b1ea79ca9b79522919
[26328a5]: https://github.com/powerman/sensitive/commit/26328a505ae993fd7f8f9ec1e06066d744ea267d
[beaa2a9]: https://github.com/powerman/sensitive/commit/beaa2a985675942193dca61571bb31a63b4a2a9c
[572e177]: https://github.com/powerman/sensitive/commit/572e177b0f35f6a146237da4493ea8b83f17ac90
[e8866d2]: https://github.com/powerman/sensitive/commit/e8866d2399fd44bf1e49b20c976d9178563cb7e8
[9aefe6a]: https://github.com/powerman/sensitive/commit/9aefe6a2c31b17bf535b7ef0967e3087581f4fdc
[f402ccd]: https://github.com/powerman/sensitive/commit/f402ccd9adf78bdddce0ed0b6c0227b702e62121

## [0.0.7] - 2021-10-23

### 📚 Documentation

- Update by @powerman in [#6]

[0.0.7]: https://github.com/powerman/sensitive/compare/%40%7B10year%7D..v0.0.7
[#6]: https://github.com/powerman/sensitive/pull/6

## [0.0.6] - 2021-04-19

### 🚀 Added

- Add Disable by @powerman in [8437122]

[0.0.6]: https://github.com/powerman/sensitive/compare/v0.0.5..v0.0.6
[8437122]: https://github.com/powerman/sensitive/commit/843712257bf5ba60c601273d2c4510423ffe5d18

## [0.0.5] - 2021-02-18

### 🚀 Added

- Add Decimal by @powerman in [421d11c]

[0.0.5]: https://github.com/powerman/sensitive/compare/v0.0.4..v0.0.5
[421d11c]: https://github.com/powerman/sensitive/commit/421d11cb43635b5bc2e136aad8ee7322db946e71

## [0.0.4] - 2020-11-09

### 🚀 Added

- Add Redact by @powerman in [19629b3]

### 🐛 Fixed

- Marshal result of `Format*Fn` for all types by @powerman in [84e41ff]

[0.0.4]: https://github.com/powerman/sensitive/compare/v0.0.3..v0.0.4
[84e41ff]: https://github.com/powerman/sensitive/commit/84e41ff1b1c901edabb5d08ca9a8a954ee1d68eb
[19629b3]: https://github.com/powerman/sensitive/commit/19629b3b202e73fc9943aaa911cb804e9a2eb5b4

## [0.0.3] - 2020-11-08

[0.0.3]: https://github.com/powerman/sensitive/compare/v0.0.2..v0.0.3

## [0.0.2] - 2020-11-08

### 🚀 Added

- Add Bytes by @powerman in [f0de514]
- Add Format by @powerman in [3922bee]

[0.0.2]: https://github.com/powerman/sensitive/compare/v0.0.1..v0.0.2
[f0de514]: https://github.com/powerman/sensitive/commit/f0de514fb73d12cc5ae68ae1e8125bf521f8c4df
[3922bee]: https://github.com/powerman/sensitive/commit/3922bee9192a4fea877dfeba5c5d1d076ed03a0a

## [0.0.1] - 2020-03-30

### 🔔 Changed

- Initial Commit by Dean Karn in [0af3bbd]
- Add .gitignore by Dean Karn in [5f76de4]

[0.0.1]: https://github.com/powerman/sensitive/compare/%40%7B10year%7D..v0.0.1
[0af3bbd]: https://github.com/powerman/sensitive/commit/0af3bbdabd56dfbb111c75957d2699f06b091ae5
[5f76de4]: https://github.com/powerman/sensitive/commit/5f76de4ee778f0495a4801dbd619701b60c9bd8d

<!-- generated by git-cliff -->
