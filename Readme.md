# These packages are to demonstrate how we enable quantum safe cryptographic algorithm in UEFI firmware.

See below reference:

[NIST PQC](https://csrc.nist.gov/projects/post-quantum-cryptography) - [Round-3 Candidate](https://csrc.nist.gov/projects/post-quantum-cryptography/round-3-submissions)

[Stateful HBS](https://csrc.nist.gov/projects/stateful-hash-based-signatures) and [NIST SP 800-208](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf)

## Feature:
1) QuantumSafePkg

This package is a wrapper for [liboqs](https://github.com/jyao1/liboqs/tree/UefiSupport) and provide quantum safe signature and key establishment algorithm.
It is similar to CryptoPkg which is a wrapper for openssl.

2) QuantumSafeLmsPkg

This package is a wrapper for [hash-sigs](https://github.com/jyao1/hash-sigs/tree/UefiSupport) and provide quantum safe LMS algorithm in [RFC 8554](https://www.rfc-editor.org/rfc/rfc8554.txt).
It is similar to CryptoPkg which is a wrapper for openssl.

3) QuantumSafeXmssRefPkg

This package is a wrapper for [xmss-reference](https://github.com/jyao1/xmss-reference/tree/UefiSupport) and provide quantum safe XMSS algorithm in [RFC 8391](https://www.rfc-editor.org/rfc/rfc8391.txt).
It is similar to CryptoPkg which is a wrapper for openssl.

## Build:
This repo uses below submodules:

  QuantumSafePkg/Library/OqsLib/liboqs

  QuantumSafeLmsPkg/Library/LmsLib/hash-sigs

  QuantumSafeXmssRefPkg/Library/XmssLib/xmss-reference

## Run:

  NOTE: Some crypto algorithm uses large stack. Please enlarge the STACK_SIZE to 8M at least to run all test in [DxeIpl](https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Core/DxeIplPeim/DxeIpl.h).

  You may also use [StackUsage](https://github.com/jyao1/EdkiiShellTool/tree/master/EdkiiShellToolPkg/StackUsage) tool to track the stack usage.

## Known limitation:
This package is only the sample code to show the concept.
It does not have a full validation and does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.


