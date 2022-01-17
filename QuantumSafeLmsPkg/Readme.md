# QuantumSafeLmsPkg

## LmsDemo.efi

`LmsDemo.efi genkey <keyname> [param_set [other_param]]` generates key (keyname.prv, keyname.pub, and keyname.aux).
`param_set` example `15_4,10_8:2000` states that we have two Merkle levels, the top has 15 levels (and uses Winternitz parameter 4), the bottom has 10 levels (and uses Winternitz parmaeter 8); up to 2000 bytes of aux data are used.
`other_param` example `seed=0123456789abcdef i=fedcba98765432` uses the specified values for the top-level LMS tree.

Sample keys are provided by QuantumSafeLmsPkg/TestKeys.

`LmsDemo.efi sign <keyname> <file1, [file2 ...]>` signs files.

`LmsDemo.efi verify <keyname> <file1, [file2 ...]>` verifies files.

`LmsDemo.efi advance <keyname> <integer>` advances keyname.prf places.
