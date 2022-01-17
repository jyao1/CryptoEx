# LightweightCryptoPkg

## Algorithm

AEAD-only: Elephant, ISAP, GIFT-COFB, TinyJambu, Romulus, Grain128-AEAD

AEAD+Hash: ASCON, Photon-Beetle, Sparkle, Xoodyak

## LwcTest.efi

`LwcTest.efi` tests all algorithms.

## LwcKatGen.efi

`LwcKatGen.efi [options] <Algorithm> <KAT-file>` generates KAT file.

`LwcKatGen.efi --algorithms` lists all algorithms.

The default KAT-file can be found at LightweightCryptoPkg/Library/LwcLib/lwc-finalists/test/kat.

## LwcKat.efi

`LwcKat.efi <Algorithm> <KAT-file> [--performance]` tests according to KAT file.

`LwcKat.efi --algorithms` lists all algorithms.

Below script can test all lwc algorithms.

```
LwcKat.efi ASCON-128 ASCON-128.txt
LwcKat.efi ASCON-128a ASCON-128a.txt
LwcKat.efi ASCON-80pq ASCON-80pq.txt
LwcKat.efi ASCON-128-Masked ASCON-128.txt
LwcKat.efi ASCON-128a-Masked ASCON-128a.txt
LwcKat.efi ASCON-80pq-Masked ASCON-80pq.txt
LwcKat.efi ASCON-128-SIV ASCON-128-SIV.txt
LwcKat.efi ASCON-128a-SIV ASCON-128a-SIV.txt
LwcKat.efi ASCON-80pq-SIV ASCON-80pq-SIV.txt
LwcKat.efi ASCON-HASH ASCON-HASH.txt
LwcKat.efi ASCON-HASHA ASCON-HASHA.txt
LwcKat.efi ASCON-XOF ASCON-XOF.txt
LwcKat.efi ASCON-XOFA ASCON-XOFA.txt
LwcKat.efi Delirium Delirium.txt
LwcKat.efi Dumbo Dumbo.txt
LwcKat.efi Esch256 Esch256.txt
LwcKat.efi Esch384 Esch384.txt
LwcKat.efi GIFT-COFB GIFT-COFB.txt
LwcKat.efi GIFT-COFB-Masked GIFT-COFB.txt
LwcKat.efi Grain-128AEAD Grain-128AEAD.txt
LwcKat.efi ISAP-A-128 ISAP-A-128.txt
LwcKat.efi ISAP-A-128A ISAP-A-128A.txt
LwcKat.efi ISAP-K-128 ISAP-K-128.txt
LwcKat.efi ISAP-K-128A ISAP-K-128A.txt
LwcKat.efi ISAP-A-128-pk ISAP-A-128.txt
LwcKat.efi ISAP-A-128A-pk ISAP-A-128A.txt
LwcKat.efi ISAP-K-128-pk ISAP-K-128.txt
LwcKat.efi ISAP-K-128A-pk ISAP-K-128A.txt
LwcKat.efi Jumbo Jumbo.txt
LwcKat.efi PHOTON-Beetle-AEAD-ENC-128 PHOTON-Beetle-AEAD-ENC-128.txt
LwcKat.efi PHOTON-Beetle-AEAD-ENC-32 PHOTON-Beetle-AEAD-ENC-32.txt
LwcKat.efi PHOTON-Beetle-HASH PHOTON-Beetle-HASH.txt
LwcKat.efi Romulus-H Romulus-H.txt
LwcKat.efi Romulus-H-XOF Romulus-H-XOF.txt
LwcKat.efi Romulus-N Romulus-N.txt
LwcKat.efi Romulus-M Romulus-M.txt
LwcKat.efi Romulus-T Romulus-T.txt
LwcKat.efi Schwaemm256-128 Schwaemm256-128.txt
LwcKat.efi Schwaemm192-192 Schwaemm192-192.txt
LwcKat.efi Schwaemm128-128 Schwaemm128-128.txt
LwcKat.efi Schwaemm256-256 Schwaemm256-256.txt
LwcKat.efi TinyJAMBU-128 TinyJAMBU-128.txt
LwcKat.efi TinyJAMBU-192 TinyJAMBU-192.txt
LwcKat.efi TinyJAMBU-256 TinyJAMBU-256.txt
LwcKat.efi TinyJAMBU-128-Masked TinyJAMBU-128.txt
LwcKat.efi TinyJAMBU-192-Masked TinyJAMBU-192.txt
LwcKat.efi TinyJAMBU-256-Masked TinyJAMBU-256.txt
LwcKat.efi XOEsch256 XOEsch256.txt
LwcKat.efi XOEsch384 XOEsch384.txt
LwcKat.efi Xoodyak Xoodyak.txt
LwcKat.efi Xoodyak-Masked Xoodyak.txt
LwcKat.efi Xoodyak-Hash Xoodyak-Hash.txt
```