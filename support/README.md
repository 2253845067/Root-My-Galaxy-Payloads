# Support feed schema

`targets-v3.json` keeps one entry for each shared exploit and KernelSU payload.
`models` lists every model that can use those exact binaries.

Each entry contains only:

- `payloadId` and `displayName`;
- one or more exact `Build.MODEL` values in `models`;
- either exact Android build displays in `builds` or verified `YYYY-MM` values
  in `securityPatchMonths`;
- `url` and `size` for the exploit and KernelSU artifacts.

Automatic selection requires a model match and all declared build constraints
to match. Omit `builds` when the payload is validated for every build in the
listed security-patch months. Omit `securityPatchMonths` for an exact-build
payload. At least one of these two constraints is required.

`targets-v2.json` remains unchanged for released 0.2.3 clients. New clients
read only schema version 3.
