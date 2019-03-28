# Developer's Guide 

## Catalog of Dependencies

The following is a list of dependencies, in no particular order.
This guide includes instructions for obtaining each of these at the relevant step(s).
You may not need all of these, depending on which portions you are building or developing.

* JDK 11 - We test and build using OpenJDK 11.0.2.
* Eclipse - It must support JDK 11. Eclipse 2018-12 or later should work. Other IDEs may work, but we have not tested them.
* Gradle 5.0 - Later versions may work, but you'll need to modify our version check.
* A C/C++ compiler - We use Visual Studio 2017 on Windows, GCC on Linux, and Xcode (Clang) on macOS.
* Git - We use git-bash on Windows. Most Linux distros have git in their repos. Xcode provides git on macOS.
* Bash - This is moot on Linux and macOS. On Windows, we use MinGW. This may be distributed with Git for Windows.
* Bison and Flex - We use MinGW on Windows. Most Linux distros have these in their reposs. Xcode provides these for macOS.
* dex2jar
* AXMLPrinter2
* HFS Explorer 0.21
* Yet Another Java Service Wrapper 12.12 - Only to build Ghidra package.
* Eclipse PDE - Only for the GhidraDev plugin.
* Eclipse CDT 8.6.0 - Only for the GhidraDev plugin
* PyDev 6.3.1 - Only for the GhidraDev plugin

There are many others automatically downloaded by Gradle from Maven Central and Bintray JCenter when building and/or setting up the development environment.

## Install Development and Build Tools

If you're on Windows, install Git.
You may also need to install MinGW.
Many of the commands given below must be executed in Bash.

Install OpenJDK 11 and make sure it's the default java.

Install Eclipse.
You can launch Eclipse with any JRE/JDK, but you'll need to ensure Eclipse knows about your JDK 11 installation.
In Eclipse, select Window -> Prefereces (Eclipse -> Preferences on macOS), then navigate to Java -> Installed JREs, and ensure a JDK 11 is configured.

Install Gradle, add it to your `PATH`, and ensure it is launched using JDK 11.

## Setup Source and Dependency Repositories

You may choose any directory for your working copy, but these instructions will assume you have cloned the source to `~/git/ghidra`.
Be sure to adjust the commands to match your chosen working directory if different than suggested:

```bash
mkdir ~/git
cd ~/git
git clone git@github.com:NationalSecurityAgency/ghidra.git
```

Ghidra's build uses artifacts named as available in Maven Central and Bintray JCenter, when possible.
Unfortunately, in some cases, the artifact or the particular version we desire is not available.
So, in addition to mavenCentral and jcenter, you must configure a flatDir-style repository for manually-downloaded dependencies.

Create `~/.gradle/init.d/repos.gradle` with the following contents:

```groovy
ext.HOME = System.getProperty('user.home')

allprojects {
    repositories {
        mavenCentral()
        jcenter()
        flatDir name:'flat', dirs:["$HOME/flatRepo"]
    }
}
```

Create the `~/flatRepo` folder to hold the manually-downloaded dependencies:

```bash
mkdir ~/flatRepo
```

If you prefer not to modify your user-wide Gradle configuration, you may use
Gradle's other init script facilities, but you're on your own.

## Get Dependencies for FileFormats:

Download `dex-tools-2.0.zip` from the dex2jar project's releases page on GitHub.
Unpack the `dex-*.jar` files from the `lib` directory to `~/flatRepo`:

```bash
cd ~/Downloads   # Or wherever
curl -OL https://github.com/pxb1988/dex2jar/releases/download/2.0/dex-tools-2.0.zip
unzip dex-tools-2.0.zip
cp dex2jar-2.0/lib/dex-*.jar ~/flatRepo/

```

Download `AXMLPrinter2.jar` from the "android4me" archive on code.google.com.
Place it in `~/flatRepo`:

```bash
cd ~/flatRepo
curl -OL https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/android4me/AXMLPrinter2.jar
```

## Get Dependencies for DMG:

Download `hfsexplorer-0_21-bin.zip` from www.catacombae.org.
Unpack the `lib` directory to `~/flatRepo.`:

```bash
cd ~/Downloads   # Or wherever
curl -OL https://sourceforge.net/projects/catacombae/files/HFSExplorer/0.21/hfsexplorer-0_21-bin.zip
mkdir hfsx
cd hfsx
unzip ../hfsexplorer-0_21-bin.zip
cd lib
cp csframework.jar hfsx_dmglib.jar hfsx.jar iharder-base64.jar ~/flatRepo/
```

## Import Gradle Project

If you want just to build Ghidra, you may skip ahead to Building Ghidra.
Otherwise, import Ghidra into Eclipse using the integrated BuildShip plugin.
Select File -> Import, expand Gradle, and select "Existing Gradle Project."
Select the root of the source repo as the root Gradle project.
Be sure to select Gradle 5.0, or point it at your local installation.
You may see build path errors until the environment is properly prepared, as described below.

*Alternatively*, you may have Gradle generate the Eclipse projects and import those instead.
This is the way to go if you'd prefer not to activate Gradle's BuildShip plugin.
From the project root:

```bash
gradle eclipse
```

Select File -> Import, expand General, and select "Existing Projects into Workspace."
Select the root of the source repo, and select "Search for nested projects."
Select all, and Finish.
You may see build path errors until the environment is properly prepared, as described below.

## Prepare the Environment

From the project root, execute:

```bash
gradle prepDev -x yajswDevUnpack
```
The `prepDev` tasks primarily include generating some source, indexing our built-in help, and unpacking some dependencies.
Regarding `yajswDevUnpack`, please see the relevant sections on GhidraServer below.
For now, we exclude the unpack task.

Optionally, to pre-compile all the language modules, you may also execute:

```bash
gradle sleighCompile
```

Refresh the projects in Eclipse.
You should not see any errors at this point, and you can accomplish many development tasks.
However, some features of Ghidra will not be functional until further steps are taken.

### Building the natives

Some of Ghidra's components are built for the native platform.
We currently support Linux, macOS, and Windows 64-bit x86 systems.
Others should be possible, but we do not test on them.

#### decompile

Install bison and flex.
Now build using Gradle:

On Linux:

```bash
gradle decompileLinux64Executable
```
On macOS:

```bash
gradle decompileOsx64Executable
```

On Windows:

```cmd
gradle decompileWin64Executable
```

#### demangler_gnu

Build using Gradle:

On Linux:

```bash
gradle demangler_gnuLinux64Executable
```
On macOS:

```bash
gradle demangler_gnuOsx64Executable
```

On Windows:

```cmd
gradle demangler_gnuWin64Executable
```

#### sleigh

The sleigh compiler has been ported to Java and integrated with Ghidra.
The native sleigh compiler may still be useful for those who'd like quicker feedback by compiling from the command line.
To build the native sleigh compiler, install bison and flex.
Now, use Gradle:

On Linux:

```bash
gradle sleighLinux64Executable
```
On macOS:

```bash
gradle sleighOsx64Executable
```

On Windows:

```cmd
gradle sleighWin64Executable
```

## Run Ghidra from Eclipse

To run or debug Ghidra from Eclipse, use the provided launch configuration (usually under the "Run" or "Debug" buttons).
If the launcher does not appear, it probably has not been marked as a favorite.
Click the dropdown next to the "Run" button and select "Run Configurations."
Then expand "Java Application" on the left to find the "Ghidra" launcher.


# Building Ghidra

To build the full Ghidra distribution, you must also build the GhidraServer.

## Get Dependencies for GhidraServer

Building the GhidraServer requires "Yet another Java service wrapper" (yajsw) version 12.12.
Download `yajsw-stable-12.12.zip` from their project on www.sourceforge.net, and place it in a directory named:
`ghidra.bin/Ghidra/Features/GhidraServer/`. Note that `ghidra.bin` must be a sibling of `ghidra`:

```bash
cd ~/Downloads   # Or wherever
curl -OL https://sourceforge.net/projects/yajsw/files/yajsw/yajsw-stable-12.12/yajsw-stable-12.12.zip
mkdir -p ~/git/ghidra.bin/Ghidra/Features/GhidraServer/
cp ~/Downloads/yajsw-stable-12.12.zip ~/git/ghidra.bin/Ghidra/Features/GhidraServer/
```

Use Gradle to unpack the wrapper for development.
From your clone:

```bash
gradle yajswDevUnpack
```

## Building the Package

Before building, you may want to update the version and release name.
These properties are kept in `Ghidra/application.properties`.

If you want it included, you must also build the GhidraDevPlugin module first.
Some supporting data will also be missing.
See the sections below for instructions to produce these components.
You may also be able to copy some of this data from a previous official distribution.

To build the full package, use Gradle:

```bash
gradle buildGhidra
```

The output will be placed in `build/dist/`.
It will be named according to the version, release name, build date, and platform.
To test it, unzip it where you like, and execute `./ghidraRun`.

# Building Supporting Data

Some features of Ghidra require the curation of rather extensive data bases.
These include the Data Type Archives and Function ID Databases, both of which require collecting header files and libraries for the relevant SDKs and platforms.
Much of this work is done by hand.
Until this process is documented, those artifacts can be extracted from an official distribution and combined with your build output.

## Building Data Type Archives

TODO

## Building FID Databases

TODO

# Developing / Building the GhidraDev Plugin

First, install the Eclipse Plugin Development Environment (PDE).
By default, the GhidraDev project is excluded from the build.
To enable it, uncomment it in `settings.gradle`.

```bash
${EDITOR:-vi} settings.gradle
```

You will need some additional runtime dependencies:

## Get Dependencies for GhidraDev

Building the GhidraDev plugin for Eclipse requires the CDT and PyDev plugins for Eclipse.
Download `cdt-8.6.0.zip` from The Eclipse Foundation, and place it in a directory named:
`ghidra.bin/GhidraBuild/EclipsePlugins/GhidraDev/buildDependencies/`. Note that
`ghidra.bin` must be a sibling of `ghidra`.
To respect the Eclipse Project's resources, you may need to download the file using a browser, or at the very least, locate a suitable mirror on your own:

```bash
cd ~/Downloads   # Or wherever
curl -OL https://$CHOOSE_YOUR_MIRROR/pub/eclipse/tools/cdt/releases/8.6/cdt-8.6.0.zip
mkdir -p ~/git/ghidra.bin/GhidraBuild/EclipsePlugins/GhidraDev/buildDependencies/
cp ~/Downloads/cdt-8.6.0.zip ~/git/ghidra.bin/GhidraBuild/EclipsePlugins/GhidraDev/buildDependencies/
```

Download `PyDev 6.3.1.zip` from www.pydev.org, and place it in the same directory:

```bash
cd ~/Downloads   # Or wherever
curl -OL https://sourceforge.net/projects/pydev/files/pydev/PyDev%206.3.1/PyDev%206.3.1.zip
cp ~/Downloads/'PyDev 6.3.1.zip' ~/git/ghidra.bin/GhidraBuild/EclipsePlugins/GhidraDev/buildDependencies/
```

Use Gradle to unpack the dependencies.
Note that these tasks will not work until you enable the GhidraDev project in `settings.gradle`.
From your clone:

```bash
gradle cdtUnpack pyDevUnpack
```

## Import the GhidraDev Project

If you're using BuildShip, simply refresh the Gradle project in Eclipse.
If you're not using BuildShip, re-run `gradle eclipse` and import the new project.
