# Test fixtures

Real vendor-format evidence used by `tests/verifier_tests.rs`.

| File | Source | License |
|---|---|---|
| `sev_snp_milan_report.bin` | [virtee/sev](https://github.com/virtee/sev) `tests/certs_data/report_milan.hex` @ `a966d06d9bf0`, hex-decoded | Apache-2.0 |
| `sev_snp_milan_vcek.der` | [virtee/sev](https://github.com/virtee/sev) `tests/certs_data/vcek_milan.der` @ `a966d06d9bf0` | Apache-2.0 |
| `tdx_quote_v4.dat` | [intel/SGX-TDX-DCAP-QuoteVerificationLibrary](https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary) `Src/AttestationApp/sampleData/tdx/quote.dat` @ `d12717e3f1f2` | BSD-3-Clause, Copyright (C) 2011-2024 Intel Corporation |
| `tdx_quote_v4_test_root.der` | same repository, `Src/AttestationApp/sampleData/tdx/trustedRootCaCert.pem`, converted to DER | BSD-3-Clause, Copyright (C) 2011-2024 Intel Corporation |

The SEV-SNP report is signed by a real Milan VCEK and verifies against the built-in AMD roots.
The TDX quote is signed through Intel's *test* root (named "Intel SGX Root CA" but not the
production root), so it only verifies with `tdx_quote_v4_test_root.der` as the trust anchor.
