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
| `cve-2026-43499-app.so` | 125360 | `1254c465ea9b7964e2a912152466b80100dd51ff6087aa7ad798c84874afc5f0` |
| `cve-2026-43499-root` | 23696 | `616e80d48634918051a63b4fe62eb97d06e88ed74f6109caec63fd7da4a4b75a` |
| `android15-6.6_kernelsu-s938b-cze1-kdp.ko` | 4651232 | `a2856b1367b9b129895b4b04282d27a4f428c6cb174040b2fb9e756e25731cc4` |
| `ksud-s938b-cze1-kdp` | 6322216 | `66c4d99f716d10460329c881df71ddb856ce253c15de53b97d6778923fdf577c` |

The exploit and root helper provide temporary root only. KernelSU artifacts are
late-load test artifacts and are not a persistent installation by themselves.
