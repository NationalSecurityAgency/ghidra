# Security Policy

## What Should Be Reported Privately
Use GitHub’s [private vulnerability reporting feature](https://github.com/NationalSecurityAgency/ghidra/security/advisories/new)
to report Ghidra vulnerabilities that could allow an attacker to compromise systems or data 
**beyond the locally running Ghidra process**, including all modes of operation (the Ghidra Server, 
headless, PyGhidra, etc). Examples of issues that are appropriate for private disclosure include:

* Vulnerabilities in network-facing components, such as the Ghidra Server, that could allow 
  unauthorized access, privilege escalation, or remote code execution.
* Flaws that allow a user of a shared Ghidra Server repository to read or modify data they are not
  authorized to access.
* Weaknesses in authentication, encryption, or other security mechanisms protecting communication
  between Ghidra components across a network.
* Imported or processed data that causes Ghidra to read, write, or execute files outside of its 
  expected area of the filesystem (for example, via path traversal or unintended invocation of
  external programs).
* Imported or processed data that causes irreversible corruption to Ghidra a project, outside the
  footprint of data being imported or processed (for example, import or analysis of a binary that 
  deletes unrelated files from the project).

## What May Be Reported Publicly
Bugs whose effects are limited to disrupting the locally running Ghidra process on data limited
to what was requested to be processed may be reported publicly as regular 
[GitHub issues](https://github.com/NationalSecurityAgency/ghidra/issues). Examples include crashes,
hangs, exceptions, memory exhaustion, and incorrect analysis results triggered by importing, 
analyzing, or otherwise processing a malformed or malicious file, provided the issue does not also 
have an impact described above. 

Scripts, extensions, and plugins run with the user’s full privileges by design. Issues arising 
solely from the actions of code the user intentionally chooses to run may also be reported publicly.
This exclusion does not cover vulnerabilities that cause code to execute without the user’s intent.

Issues reported publicly may still be labeled or described as security issues. Public reporting
allows them to be tracked, discussed, and fixed in the open.

If you are unsure whether an issue warrants private disclosure, please report it privately. If the
privately reported security issue is determined to be better suited for public disclosure, the
reviewer may close the GHSA and request that it be reported publicly as a regular issue.

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
