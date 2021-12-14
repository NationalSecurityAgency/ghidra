<img src="Ghidra/Features/Base/src/main/resources/images/GHIDRA_3.png" width="400">

# WARNING

**WARNING:** There has been a [published CVE security vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
noted in Ghidra dependencies within 2 `log4j` jar files.  We strongly encourage anyone using 
previous versions of Ghidra to remediate this issue by either upgrading to 
[Ghidra 10.1](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_10.1_build), 
or patching your current version.  To patch your current Ghidra installation, delete:

* `Ghidra/Framework/Generic/lib/log4j-api-2.12.1.jar`
* `Ghidra/Framework/Generic/lib/log4j-core-2.12.1.jar`

and replace with the newer log4j 2.15.0 version:

* [`Ghidra/Framework/Generic/lib/log4j-api-2.15.0.jar`](https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-api/2.15.0/log4j-api-2.15.0.jar)
* [`Ghidra/Framework/Generic/lib/log4j-core-2.15.0.jar`](https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.15.0/log4j-core-2.15.0.jar)

If you are running Ghidra from the development environment, please pull the latest `master` branch
(or `patch`/`stable` if applicable), and execute the following to upgrade your repo to the newer 
`log4j`: 
```
$ gradle prepdev cleanEclipse eclipse
```

---

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

## Install
To install an official pre-built multi-platform Ghidra release:  
* Install [JDK 11 64-bit][jdk11]
* Download a Ghidra [release file][releases]
* Extract the Ghidra release file
* Launch Ghidra: `./ghidraRun` (or `ghidraRun.bat` for Windows)

For additional information and troubleshooting tips about installing and running a Ghidra release, 
please refer to `docs/InstallationGuide.html` which can be found in your extracted Ghidra release 
directory. 

## Build

To create the latest development build for your platform from this source repository:

##### Install build tools:
* [JDK 11 64-bit][jdk11]
* [Gradle 6.4+ or 7.x][gradle]
* make, gcc, and g++ (Linux/macOS-only)
* [Microsoft Visual Studio][vs] (Windows-only)

##### Download and extract the source:
[Download from GitHub][master]
```
$ unzip ghidra-master
$ cd ghidra-master
```
**NOTE:** Instead of downloading the compressed source, you may instead want to clone the GitHub 
repository: `git clone https://github.com/NationalSecurityAgency/ghidra.git`

##### Download additional build dependencies into source repository: 
```
$ gradle -I gradle/support/fetchDependencies.gradle init
```

##### Create development build: 
```
$ gradle buildGhidra
```
The compressed development build will be located at `build/dist/`.

For more detailed information on building Ghidra, please read the [Developer Guide][devguide].  

## Develop

### User Scripts and Extensions
Ghidra installations support users writing custom scripts and extensions via the *GhidraDev* plugin 
for Eclipse.  The plugin and its corresponding instructions can be found within a Ghidra release at
`Extensions/Eclipse/GhidraDev/`.

### Advanced Development
To develop the Ghidra tool itself, it is highly recommended to use Eclipse, which the Ghidra 
development process has been highly customized for.

##### Install build and development tools:
* Follow the above build instructions so the build completes without errors
* Install [Eclipse IDE for Java Developers][eclipse]

##### Prepare the development environment:
``` 
$ gradle prepdev eclipse buildNatives
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
[career]: https://www.intelligencecareers.gov/nsa
[releases]: https://github.com/NationalSecurityAgency/ghidra/releases
[jdk11]: https://adoptium.net/releases.html?variant=openjdk11&jvmVariant=hotspot
[gradle]: https://gradle.org/releases/
[vs]: https://visualstudio.microsoft.com/vs/community/
[eclipse]: https://www.eclipse.org/downloads/packages/
[master]: https://github.com/NationalSecurityAgency/ghidra/archive/refs/heads/master.zip
