# Unsafe Deserialization (Object Injection) in DLR jsonconversion
 
| | |
|---|---|
| **Package** | jsonconversion (PyPI) |
| **Repository** | https://github.com/DLR-RM/python-jsonconversion |
| **Vendor** | DLR (Deutsches Zentrum für Luft- und Raumfahrt / German Aerospace Center) |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **Affected** | < 2.0.0 |
| **Fixed in** | 2.0.0 |
| **Severity** | Moderate - CVSS 3.1 **4.4** (`AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N`) |
| **Advisory** | [GHSA-gh79-j73r-7mqp](https://github.com/DLR-RM/python-jsonconversion/security/advisories/GHSA-gh79-j73r-7mqp) |
| **CVE** | Pending |
| **Reporter** | Jonathan Peri (https://github.com/periiDevl) |
 

## from github.com/DLR-RM/python-jsonconversion/security/advisories/GHSA-gh79-j73r-7mqp:
### Summary

The jsonconversion package resolves class and type identifiers from JSON input during deserialization. In affected versions, crafted JSON can cause the decoder to dynamically import Python modules and invoke application-defined from_dict() methods without an explicit allowlist. Depending on the modules and classes available in the target environment, this behavior may enable code execution.

### Details

The JSONObjectDecoder supports reconstructing Python objects from JSON metadata, including the `__jsonqualname__` and `__type__` fields.

In affected versions, the `__jsonqualname__` field is resolved by dynamically importing the specified module and looking up the requested class. If the resolved class implements from_dict(), the decoder invokes that method with data from the JSON document. Module imports can execute module-level code, and application-defined deserialization methods can perform arbitrary operations.

The `__type__` field is also resolved through type lookup logic that may dynamically locate and import Python objects.

An attacker who can supply JSON to an application that uses the affected decoding behavior may therefore be able to trigger code execution through an importable module or an available class with unsafe deserialization behavior. Exploitation depends on the application's environment and the classes and modules available to the decoder.

The fix introduces explicit allowed_classes and allowed_types parameters so applications can restrict which serialized identifiers may be resolved. The allow_untrusted_types parameter controls compatibility with unrestricted type resolution. It defaults to False; applications should keep it disabled when processing untrusted input and provide the required allowlists.

Allowlisting restricts which identifiers can be resolved, but does not guarantee that registered classes or their from_dict() methods are safe. Applications should only register trusted classes and validate deserialized data. This important user information will be added to the README.md and the relevant code parts of the package.

### Proof of concept

The following proof of concept demonstrates how crafted JSON can trigger module import side effects and invoke an application-defined from_dict() method during deserialization.

Create a Python module named gadget.py on the target's Python import path:
```
from pathlib import Path

Path("imported.txt").write_text("Module imported")

class Gadget:
    @classmethod
    def from_dict(cls, dictionary):
        Path("from_dict.txt").write_text(
            str(dictionary.get("attacker", ""))
        )
        return cls()
```
Then decode the following JSON using the affected `JSONObjectDecoder`:
```
import json
from jsonconversion.decoder import JSONObjectDecoder

payload = '{"__jsonqualname__": "gadget.Gadget", "attacker": "pwned"}'

json.loads(payload, cls=JSONObjectDecoder)
```

When the module is not already imported, resolving the class imports gadget.py, causing the module-level side effect. The decoder then invokes `Gadget.from_dict()` with the attacker-controlled dictionary, causing the second side effect.

This demonstrates that deserialization can trigger code execution through dynamically resolved classes. The example requires the attacker-controlled module to be available on the target's Python import path; it does not imply that arbitrary code execution is possible on every target without suitable importable code.

The `__type__` resolution path uses the same function to import the named module, although it is less critical since no `from_dict()` method is called afterwards.

### Impact

An attacker who can cause an application to deserialize a crafted JSON document may be able to execute Python code in the context of the application process.

The impact depends on the application's use of jsonconversion, the trustworthiness of the JSON input, and the Python modules and classes available in the target environment. In particular, module imports may execute top-level code, and resolved classes may expose application-defined from_dict() methods that process attacker-controlled data.

As this package is most likely not used frequently outside the [RAFCON](https://github.com/DLR-RM/RAFCON) project, the impact scope is expected to be rather small.

Successful exploitation could result in actions with the privileges of the affected application, potentially including disclosure, modification, or deletion of accessible data.

Applications that deserialize only trusted JSON are less exposed to this attack scenario. Applications processing untrusted JSON should upgrade to a patched version and configure explicit class and type allowlists. The unrestricted compatibility option should not be enabled for untrusted input.

## Timeline
 
| Date | Event |
|---|---|
| 2026-10-10 | Reported to DLR-RM |
| 2026-10-14 | Fix developed and verified |
| 2026-10-16 | jsonconversion 2.0.0 released with the fix |
| 2026-10-26 | GHSA-gh79-j73r-7mqp published |
 
## Credit
 
Discovered and reported by **Jonathan Peri** (https://github.com/periiDevl).
Coordinated by Johannes Ernst (https://github.com/JohannesErnst).
 
Advisory text reproduced from
[GHSA-gh79-j73r-7mqp](https://github.com/DLR-RM/python-jsonconversion/security/advisories/GHSA-gh79-j73r-7mqp),
published by the DLR-RM maintainers.
