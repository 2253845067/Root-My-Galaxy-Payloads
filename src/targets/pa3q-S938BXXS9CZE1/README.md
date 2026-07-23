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
| `cve-2026-43499-app.so` | 124960 | `6f387330a21162e42ce5f7e2e5b67ce165b7b36b3e68da2712eac30033bd3fb8` |
| `cve-2026-43499-root` | 23648 | `7211b89a6d275d64583677ca5c35c287fa9589c0a0a4729e2a2d855c8da4160c` |
| `android15-6.6_kernelsu-s938b-cze1-kdp.ko` | 4651232 | `a2856b1367b9b129895b4b04282d27a4f428c6cb174040b2fb9e756e25731cc4` |
| `ksud-s938b-cze1-kdp` | 6407096 | `fa3edcc7d168637394877b30cb1f909d762dda788ec14051f4ae79edd6562d63` |

The exploit and root helper provide temporary root only. KernelSU artifacts are
late-load test artifacts and are not a persistent installation by themselves.
