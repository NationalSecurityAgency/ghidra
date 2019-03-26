# Developer's Guide: Getting Started

Install OpenJDK 11 and make sure it's the default java.

Install Eclipse, at least version 2018-12, and ensure it is launched using OpenJDK 11.
Technically, you can launch with any JRE/JDK, but it's up to you ensure OpenJDK 11 is properly configured in Eclipse.

Optionally install Gradle 5.0, and ensure it is launched using OpenJDK 11.
These instructions assume you are using the gradle wrapper, so adjust the commands accordingly if you choose to use your own Gradle installation.

## Setup Repositories

Of course, you may choose any directory for your working copy, but these instructions will assume you have cloned the repo to `~/git`.
Be sure to adjust the commands to match your chosen working directory if different than suggested:

```bash
cd ~/git
git clone git@github.com:NationalSecurityAgency/ghidra.git
```

Ghidra's build uses artifact named as available in Maven Central and Bintray JCenter, when possible.
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

You should also create the `~/flatRepo` folder to hold the manually-downloaded dependencies:

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

At this point, you may import Ghidra into Eclipse using the integrated BuildShip plugin.
If you prefer another IDE, there's no reason it shouldn't work, but you're on your own.
Note that the GhidraDevPlugin requires Eclipse PDE.
Close this project to clean up the errors, unless you are developing the GhidraDevPlugin.
You may see build path errors until the environment is properly prepared, as described below.

## Prepare the Environment

There are a few preparatory tasks you should execute before, or immediately after, importing the project.
These tasks will build and index the online help, and place it somewhere accessible to Ghidra when launched from Eclipse, among other things.
This task also attempts to unpack some SDKs and/or larger dependencies required by Ghidra.
We do not provide these packages out-of-the-box because of technical and legal constraints on our distributing them.
These include the Eclipse CDT, PyDev for Eclipse, and "Yet another Java service wrapper."
If you would like to build the dependent modules, please see the relevant sections below.
For now, we will exclude the affected unpack tasks.
From the project root, execute:

```bash
./gradlew prepDev -x yajswDevUnpack
```

Optionally, to pre-compile all the language modules, you may also execute:

```bash
./gradlew sleighCompile
```

Refresh the Gradle project in Eclipse.
You should not see any errors at this point, and you can accomplish many development tasks.
However, some features of Ghidra will not be functional until further steps are taken.

### Building the natives

Some of Ghidra's components are built for the native platform.
We currently support Linux, macOS, and Windows 64-bit x86 systems.
Others should be possible, but we do not support them.

#### decompile

Install bison and flex.
Now build using Gradle:

On Linux:

```bash
./gradlew decompileLinux64Executable
```
On macOS:

```bash
./gradlew decompileOsx64Executable
```

On Windows:

```cmd
gradlew decompileWin64Executable
```

#### demangler_gnu

Build using Gradle:

On Linux:

```bash
./gradlew demangler_gnuLinux64Executable
```
On macOS:

```bash
./gradlew demangler_gnuOsx64Executable
```

On Windows:

```cmd
gradlew demangler_gnuWin64Executable
```

#### sleigh

The sleigh compiler has been ported to Java, and Ghidra will automatically compile slaspec files that it finds are out of date.
The native sleigh compiler may still be useful for those who'd like quicker feedback by compiling from the command line. To build the native sleigh compiler, install bison and flex.
Now, use Gradle:

On Linux:

```bash
./gradlew sleighLinux64Executable
```
On macOS:

```bash
./gradlew sleighOsx64Executable
```

On Windows:

```cmd
gradlew sleighWin64Executable
```

### Get Dependencies for GhidraDev

Building the GhidraDev plugin for Eclipse requires the CDT and PyDev plugins for Eclipse.
Download `cdt-8.6.0.zip` from The Eclipse Foundation, and place it in a directory named:
`ghidra.bin/GhidraBuild/EclipsePlugins/GhidraDev/buildDependencies/`.
`ghidra.bin` must be a sibling of `ghidra`.
To respect the CDT project's resources, you will need to download the file using a browser, or at the very least, locate a suitable mirror on your own:

```bash
cd ~/Downloads   # Or wherever
curl -OL http://$CHOOSE_YOUR_MIRROR/pub/eclipse/tools/cdt/releases/8.6/cdt-8.6.0.zip
mkdir -p ~/git/ghidra.bin/GhidraBuild/EclipsePlugins/GhidraDev/buildDependencies/
cp ~/Downloads/cdt-8.6.0.zip ~/git/ghidra.bin/GhidraBuild/EclipsePlugins/GhidraDev/buildDependencies/
```

Download `PyDev 6.3.1.zip` from www.pydev.org, and place it in the same directory:

```bash
cd ~/Downloads   # Or wherever
curl -OL https://sourceforge.net/projects/pydev/files/pydev/PyDev%206.3.1/PyDev%206.3.1.zip
cp ~/Downloads/'PyDev 6.3.1.zip' ~/git/ghidra.bin/GhidraBuild/EclipsePlugins/GhidraDev/buildDependencies/
```

Use Gradle to unpack the dependencies for development and building.
First, you will need to uncomment the GhidraDev project in the ```settings.gradle``` file.
Then, from your clone:

```bash
./gradlew cdtUnpack pyDevUnpack
```

### Get Dependencies for GhidraServer

Building the GhidraServer requires "Yet another Java service wrapper" (yajsw) version 12.12.
Note that building the full Ghidra package requires building the GhidraServer.
Download `yajsw-stable-12.12.zip` from their project on www.sourceforge.net, and place it in a directory named:
`ghidra.bin/Ghidra/Features/GhidraSerer/`:

```bash
cd ~/Downloads   # Or wherever
curl -OL https://sourceforge.net/projects/yajsw/files/yajsw/yajsw-stable-12.12/yajsw-stable-12.12.zip
mkdir -p ~/git/ghidra.bin/Ghidra/Features/GhidraServer/
cp ~/Downloads/yajsw-stable-12.12.zip ~/git/ghidra.bin/Ghidra/Features/GhidraServer/
```

Use Gradle to unpack the wrapper for development.
From your clone:

```bash
./gradlew yajswDevUnpack
```

# Build the full Ghidra package

If you've followed all of the steps above, except perhaps importing to Eclipse, you should be able to produce a build.
Before building, you may want to update the version and release name.
These properties are kept in `Ghidra/application.properties`.

If you want it included, you must also build the GhidraDevPlugin module first.
We do not yet have instructions for building the GhidraDevPlugin.
It should be relatively straightforward for anyone familiar with Eclipse PDE.

To build the full package, use Gradle:

```bash
./gradlew buildGhidra
```

The output will be placed in `build/dist/`.
It will be named according to the version, release name, build date, and platform.
To test it, unzip it where you like, and execute `./ghidraRun`.

# Building Supporting Data

Some features of Ghidra require the curation of rather extensive data bases.
These include the Data Type Archives and Function ID Databases, both of which require collecting header files and libraries for the relevant SDKs and platforms.
Much of this work is done by hand, and the results are simply copied into the build.
We intend to document these procedures as soon as we can.
In the meantime, those artifacts can always be extracted from our binary release.

## Building Data Type Archives

TODO

## Building FID Databases

TODO
