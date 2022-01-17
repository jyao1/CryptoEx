# QuantumSafeXmssRefPkg

## XmssUiGenKey.efi

`XmssUiGenKey.efi <Parameter> <keyPairFile>` generates key file.

Sample keys are provided by QuantumSafeXmssRefPkg/TestKeys.

## XmssUiSign.efi

`XmssUiSign.efi <keyPairFile> <MessageFile> <Signature+MessageFile>` signs file.

## XmssUiVerify.efi

`XmssUiVerify.efi <keyPairFile> <Signature+MessageFile>` verifies file.
