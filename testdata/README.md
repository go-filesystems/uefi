# UEFI test fixtures

Real prebuilt OVMF/EDK2 variable store images, committed verbatim so the
test suite can validate our reader against the canonical on-disk layout
that QEMU + EDK2 actually produce — not just against the bytes our own
writer emits.

## edk2-x64-vars.fd

- Size: 540,672 bytes (528 KiB)
- Source: `share/qemu/edk2-i386-vars.fd` from the QEMU 9.2.0 prebuilt
  package (`pkgx qemu.org=9.2.0`, package build dated 2024-12-12). QEMU
  ships this file as the canonical x86_64 OVMF non-volatile variable
  template (`60-edk2-x86_64.json` → `nvram-template`).
- EDK2 release embedded in the image: `edk2-stable202411` (the snapshot
  that shipped with QEMU 9.2.0's prebuilt firmware bundle).
- Layout: 72-byte `EFI_FIRMWARE_VOLUME_HEADER` at offset 0x00, then a
  `VARIABLE_STORE_HEADER` with the *authenticated* signature GUID at
  offset 0x48, then 31 `AUTHENTICATED_VARIABLE_HEADER` records (`MTC`,
  `BootOrder`, `Boot0000..Boot0006`, `PlatformLang`, `Lang`, `ConIn`,
  `ConOut`, `ErrOut`, `Timeout`, `MemoryTypeInformation`, ...).

This is the "stock" varstore an OVMF firmware writes back to disk after
its first boot. It exercises the FV-wrapped + authenticated-record code
path in our reader.

## Licence

EDK2 is licensed under BSD-2-Clause-Patent (SPDX:
`BSD-2-Clause-Patent`), which is compatible with this repository's
BSD-3-Clause licence — both are permissive and allow unrestricted
binary redistribution. The full upstream licence text lives in the
QEMU package at `share/qemu/edk2-licenses.txt`; the relevant entry is
reproduced below verbatim:

```
Copyright (c) 2019, TianoCore and contributors.  All rights reserved.

SPDX-License-Identifier: BSD-2-Clause-Patent

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

Subject to the terms and conditions of this license, each copyright holder
and contributor hereby grants to those receiving rights under this license
a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
(except for failure to satisfy the conditions of this license) patent
license to make, have made, use, offer to sell, sell, import, and otherwise
transfer this software, where such license applies only to those patent
claims, already acquired or hereafter acquired, licensable by such copyright
holder or contributor that are necessarily infringed by:

(a) their Contribution(s) (the licensed copyrights of copyright holders and
    non-copyrightable additions of contributors, in source or binary form)
    alone; or

(b) combination of their Contribution(s) with the work of authorship to
    which such Contribution(s) was added by such copyright holder or
    contributor, if, at the time the Contribution is added, such addition
    causes such combination to be necessarily infringed. The patent license
    shall not apply to any other combinations which include the
    Contribution.
```

## Why no aarch64 fixture?

The aarch64 prebuilt (`edk2-arm-vars.fd`) that ships with the same QEMU
package is 64 MiB — the full pflash slot, almost entirely 0xFF padding.
Committing 64 MiB to the repository for one fresh-from-factory varstore
that contains no actual variables would bloat clones for no benefit:
`FormatOVMF(.., OVMFAArch64)` already produces a byte-for-byte
equivalent empty store (same FV header geometry, same store header,
same trailing 0xFF). The aarch64 code path is exercised by
`TestFormatOVMF_AArch64_FixedGeometry` and `TestFormatOVMF_RoundTrip`
in the existing test suite.
