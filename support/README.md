# Support feed schema

`targets-v3.json` separates downloadable payloads from compatible devices. A
single payload entry owns one exploit and one KernelSU artifact, while
`compatibility.supportedDevices` lists every regional model that can use those
same binaries.

Automatic selection requires all of these checks to pass:

- manufacturer and an exact `Build.MODEL` entry in `supportedDevices`;
- kernel release rule and, when present, an exact kernel build version;
- exact build display and/or security-patch month when either list is present;
- SDK, primary ABI, and page size.

`kernelRelease.exact` takes precedence when it is non-empty. Otherwise
`prefix`, `contains`, and `suffix` must all be non-empty and all three bounds
must match. An empty `kernelBuildVersions`, `buildDisplays`, or
`securityPatchMonths` array means that field does not further restrict the
payload.

`targets-v2.json` remains unchanged for released 0.2.3 clients. New clients
read only schema version 3.
