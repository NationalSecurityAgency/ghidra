# Goals

Goal of this fork, is to be sink hole for the PRs to Ghidra which cannot be accepted right now due to
official team concerns of maintainability and other limitations on their side. I by no means does not
have resources to diverge from the official product too much.

I want to keep in the `master` mirror of the official repo, and in the `dev`, keep all customization.

# Changes in addition to Ghidra

- [Support for VS2019](https://github.com/kant2002/ghidra-official/commit/cd767aca016a5a34d249f0d818e2bc834207de8a)

# Ghidra Software Reverse Engineering Framework

[![Build Status](https://codevision.visualstudio.com/Ghidra/_apis/build/status/kant2002.ghidra-official?branchName=dev)](https://codevision.visualstudio.com/Ghidra/_build/latest?definitionId=106&branchName=dev)

Ghidra is a software reverse engineering (SRE) framework created and maintained by the [National Security Agency][nsa] Research Directorate. This framework includes a suite of full-featured, high-end software analysis tools that enable users to analyze compiled code on a variety of platforms including Windows, macOS, and Linux. Capabilities include disassembly, assembly, decompilation, graphing, and scripting, along with hundreds of other features. Ghidra supports a wide variety of processor instruction sets and executable formats and can be run in both user-interactive and automated modes. Users may also develop their own Ghidra plug-in components and/or scripts using Java or Python.

In support of NSA's Cybersecurity mission, Ghidra was built to solve scaling and teaming problems on complex SRE efforts, and to provide a customizable and extensible SRE research platform. NSA has applied Ghidra SRE capabilities to a variety of problems that involve analyzing malicious code and generating deep insights for SRE analysts who seek a better understanding of potential vulnerabilities in networks and systems.

To start developing extensions and scripts, try out the GhidraDev plugin for Eclipse, which is part of the distribution package.  The full release build can be downloaded from our [project homepage][project].

This repository contains the source for the core framework, features, and extensions.
If you would like to contribute, please take a look at our [contributor guide][contrib] to see how you can participate in this open source project.

If you are a U.S. citizen interested in projects like this, to develop Ghidra, and
other cybersecurity tools, for NSA to help protect our nation and its allies,
consider applying for a [career with us][career].

[nsa]: https://www.nsa.gov
[contrib]: CONTRIBUTING.md
[career]: https://www.intelligencecareers.gov/nsa
[project]: https://www.ghidra-sre.org/
