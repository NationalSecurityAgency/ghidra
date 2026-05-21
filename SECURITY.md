# Security Policy

## Reporting a security vulnerability

**Please do not file a public issue or pull request for a suspected
vulnerability.** Public reports give adversaries the same information,
at the same time, as the maintainers.

Use either of the following private channels:

1. **GitHub private vulnerability report** (preferred):
   <https://github.com/NationalSecurityAgency/ghidra/security/advisories/new>.
   This keeps the embargo, patch, and disclosure thread in one place
   and produces a CVE on publication.
2. Email the maintainers via the contact path listed at
   <https://github.com/NationalSecurityAgency/ghidra/security/policy>.

Please include in your report:

- A clear description of the vulnerability.
- Steps to reproduce (a minimal binary, headless invocation, or
  scripted test case is the single most useful artifact).
- The Ghidra version (`./ghidraRun --version` or the release archive
  filename) you tested against.
- Your assessment of impact.
- Whether you have disclosed elsewhere, and if so, where.
- How you would like to be credited in the advisory (or "anonymous").

## Scope

Ghidra parses adversary-controlled binary input (loaders for ELF, PE,
Mach-O, DEX, PDB, DWARF, COFF, archive formats) and ships a network-
reachable Ghidra server. The following are in scope for "security":

- Crash, OOM, infinite loop, or stack overflow on attacker-controlled
  input to any loader or analyzer.
- Code execution from any loader path, script path, or extension path.
- Information disclosure from the local user's projects or environment.
- Network protocol weaknesses in the Ghidra server, RMI, or
  collaborative server.
- Java deserialization vectors reachable from network or file input.

The following are not security issues:

- Slow performance on legitimately complex input. File a performance bug.
- "Ghidra disassembled my malware and now I have malware on my screen."
  That is the tool working as designed.
- Behaviour reproducible only by modifying Ghidra itself.
- User-authored scripts running outside any sandbox. The user is the
  trust boundary for scripts they place on their own machine.

## Response

For each accepted report we will:

1. Acknowledge receipt promptly via the reporting channel.
2. Confirm or dispute the issue and share an initial assessment.
3. Coordinate a fix and disclosure timeline with you, including
   embargo extension if your situation requires it.
4. Publish a GitHub Security Advisory at disclosure time. Where the
   issue meets the GHSA CNA criteria, a CVE is assigned and listed in
   the advisory.

## What you will see at disclosure time

- A published GitHub Security Advisory at
  <https://github.com/NationalSecurityAgency/ghidra/security/advisories>
  with the affected version range, CVE (where assigned), and CVSS 3.1
  base score.
- Release notes for the fixing version naming the advisory.
- Credit to the reporter as requested.

## Out-of-band coordination

For embargoes that involve multiple downstream packagers or
coordinated disclosure with other vendors, please contact the
maintainers using the channels above; we are happy to coordinate
across multiple parties on a single fix.

## Thank you

Responsible disclosure makes Ghidra better for the security community
that relies on it. We appreciate the work you are doing.
