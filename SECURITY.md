# Security Policy

## Reporting a Vulnerability
To report a security vulnerability in Ghidra, please use GitHub's private vulnerability reporting:

**[Report a vulnerability](https://github.com/NationalSecurityAgency/ghidra/security/advisories/new)**

This ensures the report is only visible to repository maintainers and allows coordinated disclosure. 
Please do not open public issues for security vulnerabilities.

Please include the following in the report:
* A brief summary of the vulnerability
* A detailed description of the vulnerability, including the affected file(s) and line numbers
* A Proof of Concept (POC) or steps for how to reproduce
* A suggested fix, if applicable
* The impact of the vulnerability, and who is affected

## Triage Phase
The Ghidra Team will independently triage the security concern based on information in the
private security advisory. A member of the Ghidra Team may respond to request more information, or
to ask general questions. This interaction will remain in the private comments of the security
advisory and will not be published.

## Draft Phase
If/when the Ghidra Team patches the vulnerability in the repo, the security advisory will move to 
the "Draft" state. The Ghidra Team will update the security advisory with the proper 
"Affected versions" and "Patch versions", and will make sure the CVSS scoring, Credits, and other 
metadata is correct.

Whenever possible, the author's original security advisory will be published as-is. However, the
Ghidra Team reserves the right to make edits to improve formatting, remove inaccuracies, or add
additional information. Additionally, Proof of Concept sections may be moved to the private 
comments by the Ghidra Team if they feel it is appropriate to do so.

## Publication
Sometime following the official release of Ghidra that includes the patch, the security advisory
will move to the "Published" state. The time frame will be based on how much time the Ghidra Team 
feels is needed for the user base to migrate to the patched version.

## CVE Information
The Ghidra Team is **currently not authorized** to generate CVEs from security advisories. It will 
be the responsibility of the original reporter to generate a CVE and notify the Ghidra Team if 
desired. The Ghidra Team may then link the CVE to the security advisory.
