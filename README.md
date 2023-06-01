<img src="Ghidra/Features/Base/src/main/resources/images/GHIDRA_3.png" width="400">

# Ghidra Software Reverse Engineering Framework

Ghidra is a software reverse engineering (SRE) framework created and maintained by the 
[National Security Agency][nsa] Research Directorate. This framework includes a suite of 
full-featured, high-end software analysis tools that enable users to analyze compiled code on a 
variety of platforms including Windows, macOS, and Linux. Capabilities include disassembly, 
assembly, decompilation, graphing, and scripting, along with hundreds of other features. Ghidra 
supports a wide variety of processor instruction sets and executable formats and can be run in both 
user-interactive and automated modes. Users may also develop their own Ghidra extension components 
and/or scripts using Java or Python.

In support of NSA's Cybersecurity mission, Ghidra was built to solve scaling and teaming problems 
on complex SRE efforts, and to provide a customizable and extensible SRE research platform. NSA has 
applied Ghidra SRE capabilities to a variety of problems that involve analyzing malicious code and 
generating deep insights for SRE analysts who seek a better understanding of potential 
vulnerabilities in networks and systems.

If you are a U.S. citizen interested in projects like this, to develop Ghidra and other 
cybersecurity tools for NSA to help protect our nation and its allies, consider applying for a 
[career with us][career].

## Security Warning

**WARNING:** There are known security vulnerabilities within certain versions of Ghidra.  Before 
proceeding, please read through Ghidra's [Security Advisories][security] for a better understanding 
of how you might be impacted.

## Install
To install an official pre-built multi-platform Ghidra release:  
* Install [JDK 17 64-bit][jdk17]
* Download a Ghidra [release file][releases]
* Extract the Ghidra release file
* Launch Ghidra: `./ghidraRun` (or `ghidraRun.bat` for Windows)

For additional information and troubleshooting tips about installing and running a Ghidra release, 
please refer to `docs/InstallationGuide.html` which can be found in your extracted Ghidra release 
directory. 

## Build

To create the latest development build for your platform from this source repository:

##### Install build tools:
* [JDK 17 64-bit][jdk17]
* [Gradle 7.3+][gradle]
* make, gcc, and g++ (Linux/macOS-only)
* [Microsoft Visual Studio][vs] 2017+ or [Microsoft C++ Build Tools][vcbuildtools] with the
  following components installed (Windows-only):
  - MSVC
  - Windows SDK
  - C++ ATL

##### Download and extract the source:
[Download from GitHub][master]
```
unzip ghidra-master
cd ghidra-master
```
**NOTE:** Instead of downloading the compressed source, you may instead want to clone the GitHub 
repository: `git clone https://github.com/NationalSecurityAgency/ghidra.git`

##### Download additional build dependencies into source repository: 
```
gradle -I gradle/support/fetchDependencies.gradle init
```

##### Create development build: 
```
gradle buildGhidra
```
The compressed development build will be located at `build/dist/`.

For more detailed information on building Ghidra, please read the [Developer Guide][devguide].

For issues building, please check the [Known Issues][known-issues] section for possible solutions.

## Develop

### User Scripts and Extensions
Ghidra installations support users writing custom scripts and extensions via the *GhidraDev* plugin 
for Eclipse.  The plugin and its corresponding instructions can be found within a Ghidra release at
`Extensions/Eclipse/GhidraDev/`.

### Advanced Development
To develop the Ghidra tool itself, it is highly recommended to use Eclipse, which the Ghidra 
development process has been highly customized for.

##### Install build and development tools:
* Follow the above [build instructions](#build) so the build completes without errors
* Install [Eclipse IDE for Java Developers][eclipse]

##### Prepare the development environment:
``` 
gradle prepdev eclipse buildNatives
```

##### Import Ghidra projects into Eclipse:
* *File* -> *Import...*
* *General* | *Existing Projects into Workspace*
* Select root directory to be your downloaded or cloned ghidra source repository
* Check *Search for nested projects*
* Click *Finish*

When Eclipse finishes building the projects, Ghidra can be launched and debugged with the provided
**Ghidra** Eclipse *run configuration*.

For more detailed information on developing Ghidra, please read the [Developer Guide][devguide]. 

## Contribute
If you would like to contribute bug fixes, improvements, and new features back to Ghidra, please 
take a look at our [Contributor Guide][contrib] to see how you can participate in this open 
source project.


[nsa]: https://www.nsa.gov
[contrib]: CONTRIBUTING.md
[devguide]: DevGuide.md
[known-issues]: DevGuide.md#known-issues
[career]: https://www.intelligencecareers.gov/nsa
[releases]: https://github.com/NationalSecurityAgency/ghidra/releases
[jdk17]: https://adoptium.net/temurin/releases
[gradle]: https://gradle.org/releases/
[vs]: https://visualstudio.microsoft.com/vs/community/
[vcbuildtools]: https://visualstudio.microsoft.com/visual-cpp-build-tools/
[eclipse]: https://www.eclipse.org/downloads/packages/
[master]: https://github.com/NationalSecurityAgency/ghidra/archive/refs/heads/master.zip
[security]: https://github.com/NationalSecurityAgency/ghidra/security/advisories
