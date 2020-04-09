# Developer's Guide

## References

- [Catalog of Dependencies](#catalog-of-dependencies)
- [Install Development and Build Tools](#install-development-and-build-tools)
- [Setup Source Repository](#setup-source-repository)
- [Setup Build Dependency Repository](#setup-build-dependency-repository)
  * [Automatic script instructions](#automatic-script-instructions)
  * [Manual download instructions](#manual-download-instructions)
- [Building Ghidra](#building-ghidra)
- [Developing Ghidra](#developing-ghidra)
  * [Prepare the Environment](#prepare-the-environment)
  * [Import Eclipse Projects](#import-eclipse-projects)
  * [Building the natives](#building-the-natives)
  * [Pre-compile Language Modules](#pre-compile-language-modules-optional)
  * [Import and Build GhidraDev project](#import-and-build-ghidradev-project-optional)
  * [Run and Debug Ghidra from Eclipse](#run-and-debug-ghidra-from-eclipse)
  * [Running tests](#running-tests)
- [Setup build in CI](#setup-build-in-ci)
- [Building Supporting Data](#building-supporting-data)
  * [Building Data Type Archives](#building-data-type-archives)
  * [Building FID Databases](#building-fid-databases)

## Catalog of Dependencies

The following is a list of dependencies, in no particular order.
This guide includes instructions for obtaining many of these at the relevant step(s).
You may not need all of these, depending on which portions you are building or developing.

* Java JDK 11 (64-bit) - Free long term support (LTS) versions of JDK 11 are provided by:
    - AdoptOpenJDK
      - https://adoptopenjdk.net/releases.html?variant=openjdk11&jvmVariant=hotspot
    - Amazon Corretto
      - https://docs.aws.amazon.com/corretto/latest/corretto-11-ug/downloads-list.html
* Eclipse - It must support JDK 11. Eclipse 2018-12 or later should work. Other IDEs may work, but we have not tested them.
    - https://www.eclipse.org/downloads/
* Gradle 5.0 or later - We use version 5.0, and tested with up to 5.6.3.
    - https://gradle.org/next-steps/?version=5.0&format=bin
* A C/C++ compiler - We use GCC on Linux, Xcode (Clang) on macOS, and Visual Studio (2017 or later) on Windows.
    - https://gcc.gnu.org/
    - https://developer.apple.com/xcode/
    - https://visualstudio.microsoft.com/downloads/
* Git - We use the official installer on Windows. Most Linux distros have git in their repos. Xcode provides git on macOS.
    - https://git-scm.com/downloads
* Bash - This is moot on Linux and macOS. On Windows, we use MinGW. This may be distributed with Git for Windows.
    - https://osdn.net/projects/mingw/releases/
* Bison and Flex - We use win-flex-bison v2.5.17. These packages may also be available in MSYS (MinGW). Most Linux distros have these in their repos. Xcode provides these for macOS.
    - https://sourceforge.net/projects/winflexbison/
* dex2jar. We use version 2.0.
    - https://github.com/pxb1988/dex2jar/releases
* AXMLPrinter2
    - https://code.google.com/archive/p/android4me/downloads
* HFS Explorer. We use version 0.21.
    - https://sourceforge.net/projects/catacombae/files/HFSExplorer/0.21/
    - https://github.com/unsound/hfsexplorer/releases (newer versions)
* Yet Another Java Service Wrapper. We use version 12.12 - Only to build Ghidra package.
    - https://sourceforge.net/projects/yajsw/files/yajsw/yajsw-stable-12.12/
* Eclipse PDE - Environment for developing the GhidraDev plugin.
    - https://www.eclipse.org/pde/
* Eclipse CDT. We use version 8.6.0 - Build dependency for the GhidraDev plugin.
    - https://www.eclipse.org/cdt/
* PyDev. We use version 6.3.1 - Build dependency for the GhidraDev plugin.
    - https://sourceforge.net/projects/pydev/files/pydev/

There are many, many others automatically downloaded by Gradle from Maven Central and Bintray JCenter when building and/or setting up the development environment.
If you need these offline, a reasonable course of action is to set up a development environment online, perhaps perform a build, and then scrape Gradle's cache.

## Install Development and Build Tools

If you're on Windows, install Git, MinGW, Bison, and Flex.
Many of the commands given below must be executed in Bash (Use git-bash or MSYS from MinGW).
**IMPORTANT**: The bison and flex executables may be named `win-bison.exe` and `win-flex.exe`.
Our build cannot currently cope with that, so you should rename them to `bison.exe` and `flex.exe`.

Install OpenJDK 11 and make sure it's the default java.

Install Eclipse.
You can launch Eclipse with any JRE/JDK, but you'll need to ensure Eclipse knows about your JDK 11 installation.
In Eclipse, select Window -> Preferences (Eclipse -> Preferences on macOS), then navigate to Java -> Installed JREs, and ensure a JDK 11 is configured.

Install Gradle, add it to your `PATH`, and ensure it is launched using JDK 11.

## Setup Source Repository

You may choose any directory for your working copy, but these instructions will assume you have cloned the source to `~/git/ghidra`.
Be sure to adjust the commands to match your chosen working directory if different than suggested:

```bash
mkdir ~/git
cd ~/git
git clone git@github.com:NationalSecurityAgency/ghidra.git
```

## Setup Build Dependency Repository

Ghidra's build uses artifacts named as available in Maven Central and Bintray JCenter, when possible.
Unfortunately, in some cases, the artifact or the particular version we desire is not available.
So, in addition to mavenCentral and jcenter, you must configure a flat directory-style repository for
manually-downloaded dependencies.

The flat directory-style repository can be created and populated automatically by a provided script, 
or manually by downloading the required dependencies.  Choose one of the two following methods:
  * [Automatic script instructions](#automatic-script-instructions)
  * [Manual download instructions](#manual-download-instructions)

### Automatic Script Instructions
The flat directory-style repository can be setup automatically by running a simple Gradle script. 
Navigate to `~/git/ghidra` and run the following:
```
gradle --init-script gradle/support/fetchDependencies.gradle init
```
The Gradle task to be executed, in this case _init_, is unimportant. The point is to have Gradle execute
the `fetchDependencies.gradle` script. If it ran correctly you will have a new `~/git/ghidra/flatRepo/` 
directory populated with the following jar files:
 * AXMLPrinter2
 * csframework
 * dex-ir-2.0
 * dex-reader-2.0
 * dex-reader-api-2.0
 * dex-tools-2.0
 * dex-translator-2.0
 * dex-writer-2.0
 * hfsx
 * hfsx_dmglib
 * iharder-base64

There will also be a new archive files at:
 * ~/git/ghidra/Ghidra/Features/GhidraServer/build/`yajsw-stable-12.12.zip`
 * ~/git/ghidra/GhidraBuild/EclipsePlugins/GhidraDev/GhidraDevPlugin/build/`PyDev 6.3.1.zip`
 * ~/git/ghidra/GhidraBuild/EclipsePlugins/GhidraDev/GhidraDevPlugin/build/`cdt-8.6.0.zip`

If you see these, congrats! Skip to [building](#building-ghidra) or [developing](#developing-ghidra). If not, continue with manual download 
instructions below...

### Manual Download Instructions

Create the `~/git/ghidra/flatRepo/` directory to hold the manually-downloaded dependencies:

```bash
mkdir ~/git/ghidra/flatRepo
```

#### Get Dependencies for FileFormats:

Download `dex-tools-2.0.zip` from the dex2jar project's releases page on GitHub.
Unpack the `dex-*.jar` files from the `lib` directory to `~/git/ghidra/flatRepo`:

```bash
cd ~/Downloads   # Or wherever
curl -OL https://github.com/pxb1988/dex2jar/releases/download/2.0/dex-tools-2.0.zip
unzip dex-tools-2.0.zip
cp dex2jar-2.0/lib/dex-*.jar ~/git/ghidra/flatRepo/

```

Download `AXMLPrinter2.jar` from the "android4me" archive on code.google.com.
Place it in `~/git/ghidra/flatRepo`:

```bash
cd ~/git/ghidra/flatRepo
curl -OL https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/android4me/AXMLPrinter2.jar
```

#### Get Dependencies for DMG:

Download `hfsexplorer-0_21-bin.zip` from www.catacombae.org.
Unpack the `lib` directory to `~/git/ghidra/flatRepo`:

```bash
cd ~/Downloads   # Or wherever
curl -OL https://sourceforge.net/projects/catacombae/files/HFSExplorer/0.21/hfsexplorer-0_21-bin.zip
mkdir hfsx
cd hfsx
unzip ../hfsexplorer-0_21-bin.zip
cd lib
cp csframework.jar hfsx_dmglib.jar hfsx.jar iharder-base64.jar ~/git/ghidra/flatRepo/
```

#### Get Dependencies for GhidraServer

Building the GhidraServer requires "Yet another Java service wrapper" (yajsw) version 12.12.
Download `yajsw-stable-12.12.zip` from their project on www.sourceforge.net, and place it in:
`~/git/ghidra/Ghidra/Features/GhidraServer/build`:

```bash
cd ~/Downloads   # Or wherever
curl -OL https://sourceforge.net/projects/yajsw/files/yajsw/yajsw-stable-12.12/yajsw-stable-12.12.zip
mkdir -p ~/git/ghidra/Ghidra/Features/GhidraServer/build/
cp ~/Downloads/yajsw-stable-12.12.zip ~/git/ghidra/Ghidra/Features/GhidraServer/build/
```

#### Get Dependencies for GhidraDev

Building the GhidraDev plugin for Eclipse requires the CDT and PyDev plugins for Eclipse.
Download `cdt-8.6.0.zip` from The Eclipse Foundation, and place it in:
`~/git/ghidra/GhidraBuild/EclipsePlugins/GhidraDev/GhidraDevPlugin/build/`:

```bash
cd ~/Downloads   # Or wherever
curl -OL 'http://www.eclipse.org/downloads/download.php?r=1&protocol=https&file=/tools/cdt/releases/8.6/cdt-8.6.0.zip'
curl -o 'cdt-8.6.0.zip.sha512' -L --retry 3 'https://www.eclipse.org/downloads/sums.php?type=sha512&file=/tools/cdt/releases/8.6/cdt-8.6.0.zip'
shasum -a 512 -c 'cdt-8.6.0.zip.sha512'
mkdir -p ~/git/ghidra/GhidraBuild/EclipsePlugins/GhidraDev/GhidraDevPlugin/build/
cp ~/Downloads/cdt-8.6.0.zip ~/git/ghidra/GhidraBuild/EclipsePlugins/GhidraDev/GhidraDevPlugin/build/
```

Download `PyDev 6.3.1.zip` from www.pydev.org, and place it in the same directory:

```bash
cd ~/Downloads   # Or wherever
curl -L -o 'PyDev 6.3.1.zip' https://sourceforge.net/projects/pydev/files/pydev/PyDev%206.3.1/PyDev%206.3.1.zip
cp ~/Downloads/'PyDev 6.3.1.zip' ~/git/ghidra/GhidraBuild/EclipsePlugins/GhidraDev/GhidraDevPlugin/build/
```

## Building Ghidra

Before building, you may want to update the version and release name.
These properties are kept in `~/git/ghidra/Ghidra/application.properties`.

To build the full package, use Gradle:

```bash
gradle buildGhidra
```

The output will be placed in `~/git/ghidra/build/dist/`.
It will be named according to the version, release name, build date, and platform.
To test it, unzip it where you like, and execute `./ghidraRun`.

__NOTE:__ Unless pre-built manually, the Eclipse GhidraDev plugin will not be included 
in the build. In addition, some other supporting data will also be missing.
See the sections below for instructions on how to produce these components.
You may also be able to copy some of these already-built components from a previous official distribution.

## Developing Ghidra

### Prepare the Environment

From the project root, execute:

```bash
gradle prepDev
```
The `prepDev` tasks primarily include generating some source, indexing our built-in help, and unpacking some dependencies.

### Import Eclipse Projects
To develop/modify Ghidra, you must first use Gradle to generate Eclipse projects.  From the project 
root:

```bash
gradle eclipse
```

Select __File -> Import__, expand General, and select "Existing Projects into Workspace."
Select the root of the source repo, and select "Search for nested projects."
Select all, and Finish.
You may see build path errors until the environment is properly prepared, as described below.

### Building the natives

Some of Ghidra's components are built for the native platform.
We currently support Linux, macOS, and Windows 64-bit x86 systems.
Others should be possible, but we do not test on them.

Ensure bison and flex are installed and in your `PATH`.
Now build using Gradle:

On Linux:

```bash
gradle buildNatives_linux64
```

On macOS:

```bash
gradle buildNatives_osx64
```

On Windows:

```bash
gradle buildNatives_win64
```

This will build the decompiler, the demangler for GNU toolchains, the sleigh compiler, and (on Windows only) the PDB parser.

### Pre-compile Language Modules (optional)

Optionally, to pre-compile all the language modules, you may also execute:

```bash
gradle sleighCompile
```

If the language modules are not pre-compiled, Ghidra will compile them at run time on an as-needed basis.

### Import and Build GhidraDev project (optional)

Developing the GhidraDev Eclipse plugin requires the _Eclipse PDE (Plug-in Development Environment)_, which 
can be installed via the Eclipse marketplace.  It is also included in the _Eclipse IDE for RCP and RAP Developers_.
To generate the GhidraDev Eclipse projects, execute:

```
gradle eclipse -PeclipsePDE
```

Import the newly generated GhidraDev projects into Eclipse. 

__Note:__ If you are getting compilation errors related to PyDev and CDT, go into Eclipse's preferences,
and under _Target Platform_, activate _/Eclipse GhidraDevPlugin/GhidraDev.target_.

See `~/git/ghidra/GhidraBuild/EclipsePlugins/GhidraDev/GhidraDevPlugin/build_README.txt`
for instructions on how to build the GhidraDev plugin.

### Run and Debug Ghidra from Eclipse

To run or debug Ghidra from Eclipse, use the provided launch configuration (usually under the "Run" or "Debug" buttons).
If the launcher does not appear, it probably has not been marked as a favorite.
Click the dropdown next to the "Run" button and select "Run Configurations."
Then expand "Java Application" on the left to find the "Ghidra" launcher.

### Running tests

For running unit tests, run

    gradle unitTestReport

for more complex integration tests run

    gradle integrationTest

For running both unit test and integration test and generate report use

    gradle combinedTestReport

## Setup build in CI

For running build in headless mode on Linux, in CI environment, or in Docker, before running tests, run

    Xvfb :99 -nolisten tcp &
    export DISPLAY=:99

this is required to make AWT happy.

## Building Supporting Data

Some features of Ghidra require the curation of rather extensive databases.
These include the Data Type Archives and Function ID Databases, both of which require collecting header files and libraries for the relevant SDKs and platforms.
Much of this work is done by hand.
The archives included in our official builds can be found in the __[ghidra-data]__ repository.

### Building Data Type Archives

This task is often done manually from the Ghidra GUI, and the archives included in our official build require a fair bit of fine tuning.
From a CodeBrowser window, select __File -> Parse C Source__.
From here you can create and configure parsing profiles, which lists headers and pre-processor options.
Then, click _Parse to File_ to create the Data Type Archive.
The result can be added to an installation or source tree by copying it to `~/git/ghidra/Ghidra/Features/Base/data/typeinfo`.

### Building FID Databases

This task is often done manually from the Ghidra GUI, and the archives included in our official build require a fair bit of fine tuning.
You will first need to import the relevant libraries from which you'd like to produce a FID database.
This is often a set of libraries from an SDK.
We include a variety of Visual Studio platforms in the official build.

From a CodeBrowser window, select __File -> Configure__.
Enable the "Function ID" plugins, and close the dialog.
Now, from the CodeBrowser window, select __Tools -> Function ID -> Create new empty FidDb__.
Choose a destination file.
Now, select __Tools -> Function ID -> Populate FidDb__ from programs.
Fill out the options appropriately and click OK.

If you'd like some details of our fine tuning, take a look at `~/git/ghidra/Ghidra/Features/FunctionID/data/building_fid.txt`.
