# These packages are to demonstrate how we enable new cryptographic algorithm in UEFI firmware.

1) quantum safe cryptography algorithm:

* [NIST PQC](https://csrc.nist.gov/projects/post-quantum-cryptography)
* [NISTIR 8309 - Status Report](https://csrc.nist.gov/publications/detail/nistir/8309/final)
* [NIST Round-3 Candidate](https://csrc.nist.gov/projects/post-quantum-cryptography/round-3-submissions)

2) stateful hash-based-signature algorithm:

* [NIST Stateful HBS](https://csrc.nist.gov/projects/stateful-hash-based-signatures)
* [NIST SP 800-208](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf)
* [RFC 8391 - XMSS](https://www.rfc-editor.org/rfc/rfc8391.txt)
* [RFC 8554 - LMS](https://www.rfc-editor.org/rfc/rfc8554.txt)

3) lightweight cryptography algorithm:

* [NIST LWC](https://csrc.nist.gov/projects/lightweight-cryptography)
* [NISTIR 8369 - Status Report](https://csrc.nist.gov/publications/detail/nistir/8369/final)
* [NIST Round-2 Finalists](https://csrc.nist.gov/Projects/lightweight-cryptography/finalists)

## Feature:
1) QuantumSafePkg

This package is a wrapper for [liboqs](https://github.com/jyao1/liboqs/tree/UefiSupport) and provide quantum safe signature and key establishment algorithm in [NIST PQC](https://csrc.nist.gov/projects/post-quantum-cryptography).
It is similar to CryptoPkg which is a wrapper for openssl.

2) QuantumSafeLmsPkg

This package is a wrapper for [hash-sigs](https://github.com/jyao1/hash-sigs/tree/UefiSupport) and provide quantum safe LMS algorithm in [RFC 8554](https://www.rfc-editor.org/rfc/rfc8554.txt).
It is similar to CryptoPkg which is a wrapper for openssl.

3) QuantumSafeXmssRefPkg

This package is a wrapper for [xmss-reference](https://github.com/jyao1/xmss-reference/tree/UefiSupport) and provide quantum safe XMSS algorithm in [RFC 8391](https://www.rfc-editor.org/rfc/rfc8391.txt).
It is similar to CryptoPkg which is a wrapper for openssl.

4) LightweightCryptoPkg

This package is a wrapper for [lwc-finalists](https://github.com/jyao1/lwc-finalists/tree/uefi_support) and provide lightweight cryptography algorithm in [NIST LWC](https://csrc.nist.gov/projects/lightweight-cryptography).
It is similar to CryptoPkg which is a wrapper for openssl.

## Build:
This repo uses below submodules:

  QuantumSafePkg/Library/OqsLib/liboqs

  QuantumSafeLmsPkg/Library/LmsLib/hash-sigs

  QuantumSafeXmssRefPkg/Library/XmssLib/xmss-reference

  LightweightCryptoPkg/Library/LwcLib/lwc-finalists

  Because key generation takes long time, some default key pair is provided for [LMS](https://github.com/jyao1/CryptoEx/tree/master/QuantumSafeLmsPkg/TestKeys) and [XMSS](https://github.com/jyao1/CryptoEx/tree/master/QuantumSafeXmssRefPkg/TestKeys). Please copy them to running folder.

## Run:

  NOTE: Some crypto algorithm uses large stack. Please enlarge the STACK_SIZE to 8M at least to run all test in [DxeIpl](https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Core/DxeIplPeim/DxeIpl.h).

  You may also use [StackUsage](https://github.com/jyao1/EdkiiShellTool/tree/master/EdkiiShellToolPkg/StackUsage) tool to track the stack usage.

  [PQC Stack Heap Usage](https://github.com/jyao1/CryptoEx/blob/master/QuantumSafePkg/PqcCryptTest/StackHeapUsage.c).

  [LMS Stack Heap Usage](https://github.com/jyao1/CryptoEx/blob/master/QuantumSafeLmsPkg/Library/LmsLib/StackHeapUsage.c).

  [XMSS Stack Heap Usage](https://github.com/jyao1/CryptoEx/blob/master/QuantumSafeXmssRefPkg/Library/XmssLib/StackHeapUsage.c).

  [LWC Stack Heap Usage](https://github.com/jyao1/CryptoEx/blob/master/LightweightCryptoPkg/LwcCryptTest/StackHeapUsage.c).

## Known limitation:
This package is only the sample code to show the concept.
It does not have a full validation and does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.


