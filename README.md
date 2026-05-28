# tsf-smb-ts

A Test Environment suite that exercises
[tsf-smb](https://github.com/interpretica-io/tsf-smb) (`tapi_smb`) against a
Samba server on the agent it runs on.

| Test | What it checks |
|---|---|
| `detect` | the SMB client is found (Samba), the capability table, listing a server's shares, a wrong password → `EACCES` |
| `serve_files` | the agent serves a usershare of its own, connects back, and round-trips files: write/read byte-exact, `exists`, mkdir, ls, unlink, rmdir, get-missing → `ENOENT` |
| `negotiate` | a default connection negotiates SMB3.1.1, a cap of SMB2.1 is obeyed, macOS is refused a dialect it cannot force |
| `audit` | a server built with SMB1 on and a guest-writable share is read over the wire and every planted weakness reported through tsf-cybersec |

The agent is both server and client: it serves a share and connects to
`localhost`. The audit's SMB1/signing findings are cross-checked against the
same negotiation `nmap` reports.

## Running it

Needs Docker and `test-environment` as a sibling directory:

```bash
./scripts/run.sh docker guess --cfg=localhost
```

The build image sets up a Samba server (`scripts/docker/build/Dockerfile`):
SMB1 enabled and a guest-writable `public` share on purpose, a user `alice`,
and a usershares directory owned by the agent's group at mode `01770` — smbd
refuses to serve a usershare from a world-writable directory. `conf/external.yml`
names the `tsf-*` repositories; point a `url` at a local checkout while
developing. Requires a real Test Agent with `ta_rpcprovider`.

Verified green against Samba 4.17 on Debian 12.
