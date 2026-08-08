# Root My Galaxy Payloads

This repository contains the device-specific native side of
[Root My Galaxy](https://github.com/2253845067/Root-My-Galaxy):

- exact firmware profiles and offsets;
- the app-domain CVE-2026-43499 exploit source and compiled payload;
- the app bootstrap helper source;
- the verified KernelSU late-load build artifacts;
- the support feed consumed by the application.

It intentionally does not contain Android application source code.

## Supported payloads

| Payload | Compatible models | Kernel version | Status |
| --- | --- | --- | --- |
| `pa3q-S938BXXS9CZE1` | Galaxy S25 Ultra `SM-S938B` (`S938BXXS9CZE1`) | `android15-6.6` | Device-tested |
| `pa3q-S938NKSUACZF1` | Galaxy S25 Ultra `SM-S938N` (`S938NKSUACZF1`) | `android15-6.6` | Device-tested |
| `pa3q-S9380ZHUBCZF1` | Galaxy S25 Ultra `SM-S9380` (`S9380ZHUBCZF1`) | `android15-6.6` | Device-tested |
| `pa3q-S9380ZCUBCZF1` | Galaxy S25 Ultra `SM-S9380` (`S9380ZCUBCZF1`) | `android15-6.6` | Exploit extracted from APK, kernel strings TBD |
| `galaxy-s25-series-2026-06-07` | Galaxy S25, S25+, S25 Edge, and S25 Ultra regional models | `6.6.98` | Device-tested |
| `e3q-S928USQS6DZF2` | Galaxy S24 Ultra `SM-S928U` | `6.1.145` | Hardware debugging in progress |
| `e2s-S926BXXUEDZDR` | Galaxy S24+ `SM-S926B` | `6.1.157` | Device-tested |
| `essi-A566EXXSCCZG6` | Galaxy A56 5G `SM-A566E` | `6.6.102` | Device-tested |
| `a36xq-A366WVLS3AYG1` | Galaxy A36 5G `SM-A366W` | `6.6.46` | Device-tested |
| `dm3q-S9180ZHS8FZF5` | Galaxy S23 Ultra `SM-S9180` | `5.15.189` | Test in progress |
| `r9q-S9010ZCSBGZE3` | Galaxy S22 `SM-S9010` | `android12-5.10` | Exploit from APK, offsets TBD |
| `r9q-S9060ZCSBGZE3` | Galaxy S22+ `SM-S9060` | `android12-5.10` | Exploit from APK, offsets TBD |
| `r9q-S9080ZCSBGZE3` | Galaxy S22 Ultra `SM-S9080` | `android12-5.10` | Exploit from APK, offsets TBD |
| `dm1q-S9110ZCS8FZG1` | Galaxy S23 FE `SM-S9110` | `android13-5.15` | Exploit from APK, offsets TBD |
| `dm2q-S9160ZCS8FZG1` | Galaxy S23+ `SM-S9160` | `android13-5.15` | Exploit from APK, offsets TBD |
| `dm3q-S9180ZCS8FZG1` | Galaxy S23 Ultra `SM-S9180` | `android13-5.15` | Exploit from APK, offsets TBD |
| `e1s-S9210ZCS6DZG1` | Galaxy S24 `SM-S9210` | `android14-6.1` | Exploit from APK, offsets TBD |
| `e2s-S9260ZCS6DZG1` | Galaxy S24+ `SM-S9260` | `android14-6.1` | Exploit from APK, offsets TBD |
| `e3q-S9280ZCS6DZG1` | Galaxy S24 Ultra `SM-S9280` | `android14-6.1` | Exploit from APK, offsets TBD |
| `pa3q-S9310ZCSCCZG1` | Galaxy S25 `SM-S9310` | `android15-6.6` | Exploit from APK, offsets TBD |
| `pa3q-S9360ZCSCCZG1` | Galaxy S25+ `SM-S9360` | `android15-6.6` | Exploit from APK, offsets TBD |
| `pa3q-S9370ZCS9CZG1` | Galaxy S25 Ultra `SM-S9370` | `android15-6.6` | Exploit from APK, offsets TBD |
| `pa3q-S9370ZCU8CZF1` | Galaxy S25 Ultra `SM-S9370` | `android15-6.6` | Exploit from APK, offsets TBD |
| `pa3q-S9380ZCSCCZG1` | Galaxy S25 Ultra `SM-S9380` | `android15-6.6` | Exploit from APK, offsets TBD |
| `q7q-F7610ZCS9GZF1` | Galaxy Z Flip 6 `SM-F7610` | `android15-6.6` | Exploit from APK, offsets TBD |
| `q7q-F7660ZCSBBZG3` | Galaxy Z Flip 7 `SM-F7660` | `android15-6.6` | Exploit from APK, offsets TBD |
| `q7q-F9460ZCS9GZF1` | Galaxy Z Flip 6 `SM-F9460` | `android15-6.6` | Exploit from APK, offsets TBD |
| `q7q-F9560ZCS4DZG3` | Galaxy Z Fold 6 `SM-F9560` | `android15-6.6` | Exploit from APK, offsets TBD |
| `q7q-F9660ZCSBBZG3` | Galaxy Z Fold 7 `SM-F9660` | `android15-6.6` | Exploit from APK, offsets TBD |

Schema version 3 keeps each exploit and KernelSU artifact once. Its flat
`models` and `kernelVersions` arrays define runtime compatibility. See
[`support/README.md`](support/README.md) for the matching rules.

The port is based on the exploit source published at
<https://github.com/NebuSec/CyberMeowfia/tree/main/IonStack/CVE-2026-43499/exploit>.

## Feed delivery

Root My Galaxy resolves the payload repository's current commit first and
fetches `support/targets-v3.json` and every artifact from that immutable
commit. Per-artifact SHA-256 fields and manifest signatures are not part of
schema version 3. `targets-v2.json` is retained for released 0.2.3 clients.

## Build

```sh
make TARGET=pa3q-S938BXXS9CZE1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=pa3q-S938NKSUACZF1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=pa3q-S9380ZCUBCZF1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=e3q-S928USQS6DZF2 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=e2s-S926BXXUEDZDR ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=essi-S721NKSSCDZF3 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=e1s-S921BXXSFDZF2 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=a15-A155NKSS6BYH1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=essi-A566EXXSCCZG6 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=a36xq-A366WVLS3AYG1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=dm3q-S9180ZHS8FZF5 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=dm1q-S9110ZCS8FZG1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=dm2q-S9160ZCS8FZG1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=dm3q-S9180ZCS8FZG1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=e1s-S9210ZCS6DZG1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=e2s-S9260ZCS6DZG1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=e3q-S9280ZCS6DZG1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=pa3q-S9310ZCSCCZG1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=pa3q-S9360ZCSCCZG1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=pa3q-S9370ZCS9CZG1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=pa3q-S9370ZCU8CZF1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=pa3q-S9380ZCSCCZG1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=q7q-F7610ZCS9GZF1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=q7q-F7660ZCSBBZG3 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=q7q-F9460ZCS9GZF1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=q7q-F9560ZCS4DZG3 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=q7q-F9660ZCSBBZG3 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=r9q-S9010ZCSBGZE3 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=r9q-S9060ZCSBGZE3 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=r9q-S9080ZCSBGZE3 ANDROID_NDK_HOME=/path/to/android-ndk
```

Outputs:

```text
build/<profile>/cve-2026-43499
build/<profile>/cve-2026-43499-app.so
build/<profile>/cve-2026-43499-root
```

The release app payload is built with:

```sh
make TARGET=essi-S721NKSSCDZF3 ANDROID_NDK_HOME=/path/to/android-ndk release
```

The complete firmware-to-profile procedure is recorded in
[`docs/PORTING.md`](docs/PORTING.md). Samsung-specific KernelSU changes and
versioned artifacts are documented in [`kernelsu/README.md`](kernelsu/README.md).
The exact S921B DZF2 analysis is recorded separately in
[`docs/SM-S921B-S921BXXSFDZF2.md`](docs/SM-S921B-S921BXXSFDZF2.md), and the
S928U/S928U1 DZF2 analysis is in
[`docs/SM-S928U1-S928U1UES6DZF2.md`](docs/SM-S928U1-S928U1UES6DZF2.md). S921B
is an Exynos 2400 target and is not a Qualcomm/Snapdragon reference for E3Q.
The 5.10 A15 analysis is in
[`docs/SM-A155N-A155NKSS6BYH1.md`](docs/SM-A155N-A155NKSS6BYH1.md).
The SM-A566E CCZG6 analysis and validation record is in
[`docs/SM-A566E-A566EXXSCCZG6.md`](docs/SM-A566E-A566EXXSCCZG6.md).
The SM-S926B DZDR analysis and device-validation record is in
[`docs/SM-S926B-S926BXXUEDZDR.md`](docs/SM-S926B-S926BXXUEDZDR.md).
The SM-A366W AYG1 device validation is in
[`docs/SM-A366W-A366WVLS3AYG1.md`](docs/SM-A366W-A366WVLS3AYG1.md).

Use only on devices you own or are explicitly authorized to test.
