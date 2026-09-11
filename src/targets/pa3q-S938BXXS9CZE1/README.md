# pa3q-S938BXXS9CZE1

Target profile for the Samsung Galaxy S25 Ultra `SM-S938B` XSG firmware.

```text
model: SM-S938B
device: pa3q
build: BP4A.251205.006.S938BXXS9CZE1
kernel release: 6.6.98-android15-8-pe17667d-abogkiS938BXXS9CZE1-4k
KMI: android15-6.6
page size: 4096
```

The app-domain payload was executed successfully on matching hardware. The
successful run reached `done=1 root=1` on exploit attempt 5/24. The profile is
exact-firmware only; it must not be used on other S938B builds or S9380/S938N
variants.

Published artifacts and SHA-256 values:

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| `cve-2026-43499` | 95936 | `8e45cf8ce4f868738fe1569289efe343f33c5261de46b4e6ff857dada1b91744` |
| `cve-2026-43499-app.so` | 125504 | `73e9d4867083a5fa18d399472898d774579414445168e46713a757d33480d4e0` |
| `cve-2026-43499-root` | 23696 | `616e80d48634918051a63b4fe62eb97d06e88ed74f6109caec63fd7da4a4b75a` |
| `android15-6.6_kernelsu-s938b-cze1-kdp.ko` | 334240 | `b075185419155a0e3e2b7afe448a1b9e4adc4f53e4bd0909e2981a6158e5c184` |
| `ksud-s938b-cze1-kdp` | 4978024 | `de5db6da416d88d1070041fb5659eececfd75c1f04f7cdbdf5ba5ebc96c5e6a4` |

The exploit and root helper provide temporary root only. KernelSU artifacts are
late-load test artifacts and are not a persistent installation by themselves.

## KernelSU symbol audit

Samsung's `SM-S938B_16_Opensource.zip` was rebuilt with the CZE1 target
configuration to obtain a debug, unstripped AArch64 `vmlinux`. The public tree
does not contain all vendor dependencies: `CONFIG_CHARGER_MAX77968` and
`CONFIG_SEC_MM` were disabled to make the public-source link complete.
Consequently this ELF is suitable as a reconstructed symbol-audit target, but
it is not Samsung's exact or bit-for-bit CZE1 `vmlinux.elf`.

The KernelSU v3.3.0 module audit against that reconstructed ELF and its
`Module.symvers` produced:

```text
undefined symbols: 221
module version entries: 0
missing from target symbol table: 0
symbols resolved from kallsyms rather than target exports: 67
undefined symbols intentionally without module CRC: 221
target CRC mismatches: 0
```

Reconstruction outputs:

| File | SHA-256 |
| --- | --- |
| `vmlinux` | `1d36b4ef66ba820d0c4f5d6240862eb5b668fb509a5e939e620c71efe0600d96` |
| `Module.symvers` | `9d499d8e04f9b1de051f37a721fd2ff649015832c21c818bb1c54262533fd600` |
| `System.map` | `fae3b40f1a7ab730b09cbd1b40efc520fc180e78305e01fc63a97000bb1a16fe` |

The reconstructed ELF reports
`6.6.98-pe17667d-abogkiS938BXXU9CZDP-4k`; the stock CZE1 kernel reports
`6.6.98-android15-8-pe17667d-abogkiS938BXXS9CZE1-4k`. An official CZE1 ELF,
or a bit-for-bit recovery of it, is still required before this can be called a
complete exact-target audit. The KernelSU module has not yet been loaded on
S938B CZE1 hardware.
