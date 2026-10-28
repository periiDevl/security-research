# Path Traversal / Arbitrary File Write in CNES py-hydroweb

| | |
|---|---|
| **Package** | py-hydroweb |
| **Repository** | https://github.com/CNES/py-hydroweb |
| **Vendor** | CNES (Centre National d'Études Spatiales) |
| **CWE** | CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) |
| **Affected** | < 1.3.3 |
| **Fixed in** | 1.3.3 (2026-10-12) |
| **Severity** | High - CVSS 3.1 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H) |
| **CVE** | Pending |
| **Reporter** | Jonathan Peri (https://github.com/periiDevl) |

## Summary

py-hydroweb is CNES's Python client for downloading hydrological data from
the hydroweb.next platform. The client derives the local output filename from
the server-supplied Content-Disposition response header without sanitizing
it, allowing a malicious, compromised, or spoofed server to write files
outside the intended download directory.

## Details

When saving a downloaded file, the client reads the filename parameter from
the Content-Disposition header and uses it directly to construct the local
output path. The path is not normalized, and no check confirms that the
resulting path remains inside the configured download directory, so
parent-directory references in the header are honoured during the write.

## Proof of Concept

A response carrying a header such as:

```http
Content-Disposition: attachment; filename="../../example/outside-download-dir.txt"
```

results in the file being written outside the configured download directory
rather than being rejected or constrained to it.

## Impact

An attacker who controls the server, compromises it, or is positioned to
tamper with responses in transit can write arbitrary files to any location
the invoking user can write to. Depending on where the client runs and with
what privileges, this can mean overwriting configuration or scripts, data
corruption, or code execution on the next run of an overwritten file.

## Remediation

Upgrade to py-hydroweb 1.3.3 or later. The fix sanitizes the filename taken
from Content-Disposition before it is used to build the local file path.

## Timeline

| Date | Event |
|---|---|
| 2026-10-10 | Reported to CNES |
| 2026-10-12 | A fix by CNES was proposed and then verified |
| 2026-10-12 | CNES released 1.3.3 with the fix |
| 2026-10-19 | Public advisory published and CVE requested via MITRE |

## Vendor Acknowledgment

CNES published a vulnerability notice on the hydroweb.next platform news page
on 2026-10-11, crediting the report:

> Thanks to Jonathan Peri for alerting us.
https://web.archive.org/web/20261019205822/https://hydroweb.next.theia-land.fr/news

## References

- CNES vulnerability notice - https://hydroweb.next.theia-land.fr/news
  ([archived 2026-10-19](https://web.archive.org/web/20261019205822/https://hydroweb.next.theia-land.fr/news))
- Fixed release on PyPI - https://pypi.org/project/py-hydroweb/1.3.3/
