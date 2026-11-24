# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.2] - 2026-11-24

### 📚 Documentation

- Mention log/slog and decimal balances in README by @powerman in [485a437]
- Link third-party packages and mention log/slog in doc.go by @powerman in [d08e2aa]

[0.7.2]: https://github.com/powerman/sensitive/compare/v0.7.1..v0.7.2
[485a437]: https://github.com/powerman/sensitive/commit/485a437b1fe24b9c0b1f661103ece2b67d708d26
[d08e2aa]: https://github.com/powerman/sensitive/commit/d08e2aa58bd2802deaa32235324451059a43341e

## [0.7.1] - 2026-11-24

### ⚡ Performance

- Pool crypt state and skip reflect for common types by @powerman in [22c6e00]

### 📚 Documentation

- Add rbranson/camo to comparison table by @powerman in [87ca706]

[0.7.1]: https://github.com/powerman/sensitive/compare/v0.7.0..v0.7.1
[87ca706]: https://github.com/powerman/sensitive/commit/87ca7060a26627f1d93ba658dac73cce1aa87c26
[22c6e00]: https://github.com/powerman/sensitive/commit/22c6e00962b0863b97d6037c58001039da28dddf

## [0.7.0] - 2026-11-23

### ➖ Removed

- **⚠️ BREAKING!** Drop empty-output as nil by @powerman in [19ebad3]

### 🚀 Added

- Implement slog.LogValuer for Ref and Handle by @powerman in [162326d]
- Support named types in Ref and Handle by @powerman in [26a11eb]
- Add CmpExporter for comparing secrets with go-cmp by @powerman in [7f143de]

### 🔔 Changed

- Require Go 1.26 by @powerman in [11783f0]
- Order tasks in mise.toml like the template by @powerman in [517dadc]
- **⚠️ BREAKING!** Enable Redact() by default by @powerman in [b287960]
- **⚠️ BREAKING!** Redact all numeric types as 123 by @powerman in [7f2c3bc]
- Export ErrTextSyntax and ErrScanConversion by @powerman in [c79283e]

### 🐛 Fixed

- Make New and Make of the zero value equal to the zero Ref and Handle by @powerman in [2c05606]
- Output nil instead of breaking the document for unsupported Ref types by @powerman in [b9cae5a]
- Treat only a nil interface as zero in New and IsZero of Ref[any] by @powerman in [6e26005]
- Keep JSON input out of Ref and Handle unmarshal errors by @powerman in [64d5385]

### 📚 Documentation

- Mark fmt verb coverage for rsjethani/secret and andrewbenton/go-secrets by @powerman in [9425ec1]
- Drop redundant Redact() call from basic example by @powerman in [2b462ec]
- Explain why slog.LogValuer complements marshalers by @powerman in [db59748]
- Fix stale statements by @powerman in [c0de0dc]
- Document deterministic encryption trade-off by @powerman in [3529b0d]
- Document that Make(NaN) != Make(NaN) by @powerman in [7146998]
- Describe fmt, marshaler and LogValuer output as cosmetic by @powerman in [461815f]
- Fix fmt.State reference in state comment by @powerman in [eccf736]
- Guard slice bounds in custom format examples by @powerman in [9a46c5e]
- Warn about unsynchronized changes to Format<type>Fn variables by @powerman in [1b4e7f7]
- Condense redaction docs and unify Format<Type>Fn spelling by @powerman in [2707263]

### 📦️ Dependencies

- **(deps)** Upgrade go and golangci-lint by @powerman in [d3fc144]
- **(deps)** Upgrade go modules by @powerman in [a3dcb16]
- **(deps)** Upgrade lint-sensitive to v0.5.0 by @powerman in [e8dce0a]
- **(deps)** Upgrade go and golangci-lint by @powerman in [07ce83d]
- **(deps)** Mise up by @powerman in [0c5b696]
- **(deps)** Upgrade go and golangci-lint by @powerman in [4219fd0]
- **(deps)** Upgrade tools by @powerman in [adff78d]
- **(deps)** Upgrade go modules by @powerman in [d03fa68]

[0.7.0]: https://github.com/powerman/sensitive/compare/v0.6.1..v0.7.0
[d3fc144]: https://github.com/powerman/sensitive/commit/d3fc144cc81f1b7b2d89f9f560612b71ed440027
[a3dcb16]: https://github.com/powerman/sensitive/commit/a3dcb16cc593a4d54587fb85dd22b08853c106aa
[e8dce0a]: https://github.com/powerman/sensitive/commit/e8dce0afb0f467fab670daca1ebbcc12da676ab9
[07ce83d]: https://github.com/powerman/sensitive/commit/07ce83df226b89e2a83865b1f70f8e9f57da14b2
[11783f0]: https://github.com/powerman/sensitive/commit/11783f00b34c19892b493349d5faca5ffef17c37
[0c5b696]: https://github.com/powerman/sensitive/commit/0c5b6968c2ea2a62d6803bb22d5752dc1695bde6
[517dadc]: https://github.com/powerman/sensitive/commit/517dadce7a11fc92065b947624f3a39e165f83a3
[9425ec1]: https://github.com/powerman/sensitive/commit/9425ec1eac3dea03bc5102be221138ee9594e8c8
[4219fd0]: https://github.com/powerman/sensitive/commit/4219fd0253ca3295686cb9643f63897248ffa383
[adff78d]: https://github.com/powerman/sensitive/commit/adff78dfa337cf4ee803b1ac1fea425e229193cd
[d03fa68]: https://github.com/powerman/sensitive/commit/d03fa687726593e890155c991c790244ce2bfd5e
[b287960]: https://github.com/powerman/sensitive/commit/b28796081777d8cb3392aed2c8ff99b582b6434c
[19ebad3]: https://github.com/powerman/sensitive/commit/19ebad3ae9eb9a9824b49f3d30405855efd7d6fb
[7f2c3bc]: https://github.com/powerman/sensitive/commit/7f2c3bc46ffdadc3046ef3ec700dbe3f190f8946
[2b462ec]: https://github.com/powerman/sensitive/commit/2b462ecf29467664a771a4e4248db597a3b30cf7
[162326d]: https://github.com/powerman/sensitive/commit/162326dadb01b5c4ec73dafa266fc7602dc254f0
[db59748]: https://github.com/powerman/sensitive/commit/db597489dd72e8b3b34ebf08bd7fb2fac05ccc20
[c0de0dc]: https://github.com/powerman/sensitive/commit/c0de0dccfc8e6c213f6d5751e3499c62e2d75933
[3529b0d]: https://github.com/powerman/sensitive/commit/3529b0d29c6f9950f3b87b74e3572caf6446f103
[7146998]: https://github.com/powerman/sensitive/commit/71469989ed6ffe2f5961203d1e27d7dc20985b23
[461815f]: https://github.com/powerman/sensitive/commit/461815f86760f1f514ba92b216570c53f752ef57
[2c05606]: https://github.com/powerman/sensitive/commit/2c056066abdb32f569253fc1171d662940883bb4
[26a11eb]: https://github.com/powerman/sensitive/commit/26a11eb751de0cb9904a944e9e9ea28c44adf9c5
[b9cae5a]: https://github.com/powerman/sensitive/commit/b9cae5ab84c2fd019bdc7392ec978514ba7e3da6
[6e26005]: https://github.com/powerman/sensitive/commit/6e26005d5f2ed174ec803a0c3083ba536872ab5c
[eccf736]: https://github.com/powerman/sensitive/commit/eccf73680a0df4d0207476e4ae1b10b0a4980ae5
[9a46c5e]: https://github.com/powerman/sensitive/commit/9a46c5ebacfa5921f8d0b9603557972ed98d898d
[c79283e]: https://github.com/powerman/sensitive/commit/c79283eaeec22f1b6435543b5afc699e6794e62d
[1b4e7f7]: https://github.com/powerman/sensitive/commit/1b4e7f7ea6ffb405d1e7d73648d623c1ba4d7001
[64d5385]: https://github.com/powerman/sensitive/commit/64d5385950d26f2a2df8152454d624da328d45dd
[2707263]: https://github.com/powerman/sensitive/commit/27072631743a76ee7f2d089eafbecae57b5f6414
[7f143de]: https://github.com/powerman/sensitive/commit/7f143dec25a40718be4d204686eeb25128e62b96

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
