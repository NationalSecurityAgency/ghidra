# GhidraDev Eclipse Plugin
GhidraDev provides support for developing and debugging Ghidra scripts and modules in Eclipse.

The information provided in this document is effective as of GhidraDev 5.0.1 and is subject to
change with future releases.

## Table of Contents
 1. [Change History](#change-history)
 2. [Minimum Requirements](#minimum-requirements)
 3. [Optional Requirements](#optional-requirements)
 4. [Installing](#installing)
    * [Manual Installation in Eclipse (offline)](#manual-installation-in-eclipse-offline)
    * [Manual Installation in Eclipse (online)](#manual-installation-in-eclipse-online)
    * [Automatic Installation through Ghidra](#automatic-installation-through-ghidra)
 5. [GhidraDev Features](#ghidradev-features)
    * [New Ghidra Script](#new-ghidra-script)
    * [New Ghidra Script Project](#new-ghidra-script-project)
    * [New Ghidra Module Project](#new-ghidra-module-project)
    * [Import Ghidra Module Source](#import-ghidra-module-source)
    * [Export Ghidra Module Extension](#export-ghidra-module-extension)
    * [Preferences](#preferences)
    * [Link Ghidra](#link-ghidra)
 6. [Launching and Debugging Ghidra](#launching-and-debugging-ghidra)
 7. [PyDev Support](#pydev-support)
    * [Installing PyDev](#installing-pydev)
    * [Configuring PyDev](#configuring-pydev)
 8. [Upgrading](#upgrading)
 9. [Uninstalling](#uninstalling)
 10. [Frequently Asked Questions](#frequently-asked-questions)
 11. [Additional Resources](#additional-resources)
 12. [Building](#building)

## Change History
__5.0.1:__
* Fixed a bug that prevented Ghidra from discovering the Ghidra module project when launched with
  the PyGhidra run configuration. 

__5.0.0:__
* Added support for PyGhidra.

__4.0.1:__
* New Ghidra module projects now contain a default `README.md` file.
* Fixed a bug that prevented an imported module source project from being discovered by Ghidra when
  launched with the project's run/debug configuration.

__4.0.0:__
* GhidraDev has been upgraded to be compatible with Ghidra 11.2 and later. It is not backwards
  compatible with versions of Ghidra prior to 11.2. Older versions of GhidraDev will report an 
  error when trying to link against Ghidra 11.2 or later.
* GhidraDev now requires Eclipse 2023-12 4.30 or later.
* GhidraDev now requires JDK 21.
* Fixed an issue that could result in a `GhidraHelpService` exception when launching
  Ghidra. GhidraDev now properly enforces that Ghidra is only launched with `Utility.jar` on the
  initial classpath.
  
__3.1.0:__
* GhidraDev has been upgraded to be compatible with Ghidra 11.1 and later. Older versions of
  GhidraDev will report an error when trying to link against Ghidra 11.1 or later.
* GhidraDev now supports importing a Ghidra module source directory. This will work best with Ghidra
  module projects created from Ghidra 11.1 or later.
* GhidraDev will now fail to launch Ghidra if a top-level `build` directory is detected. Presence of
  this intermediate build artifact can cause Ghidra to have runtime/debugging issues.

__3.0.2:__
* GhidraDev no longer throws an IOException when performing a `Link Ghidra` action on a Ghidra 
  project whose original Ghidra installation moved.
* GhidraDev now prevents unsupported versions of PyDev from being used.

__3.0.1:__
* Exporting a Ghidra Module Extension produces an intermediate `build` directory within the 
  project. This `build` directory now gets automatically cleaned up to avoid Ghidra 
  runtime/debugging issues.
* GhidraDev now prevents unsupported Ghidra source repositories from being added as a Ghidra
  installations.

__3.0.0:__
* GhidraDev now requires Eclipse 2021-12 4.22 or later.
* GhidraDev now requires JDK 17.
* Fixed an issue that could cause old extensions to incorrectly remain on the Ghidra project 
  classpath after performing a `Link Ghidra`.

__2.1.5:__
* Eclipse Python breakpoints now work when Eclipse installs PyDev in .p2 bundle pool directory.

__2.1.4:__
* Fixed exception that occurred when performing a `Link Ghidra` on projects  that use a Gradle 
  classpath container.

__2.1.3:__
* Fixed a bug that prevented Ghidra projects from recognizing extensions installed in the user's 
  `~/.ghidra/.ghidra_<version>/Extensions` directory.

__2.1.2:__
* Fixed exception that occurred when creating a new Ghidra scripting project if a `~/ghidra_scripts`
  directory does not exist.

__2.1.1:__
* Python debugging now works when PyDev is installed via the Eclipse `dropins` directory.
* Fixed a bug in the check that prevents Ghidra projects from being created within the Ghidra 
  installation directory.
  
__2.1.0:__
* Added support for Ghidra 9.1.  GhidraDev 2.1.0 will be unable to create new Eclipse projects for
  versions of Ghidra earlier than 9.1.
* Prevented Ghidra projects from being created inside of a Ghidra installation directory.
* Added an `Environments` tab to the Ghidra run configuration for setting environment variables
  when launching Ghidra.

__2.0.1:__
* Fixed exception that occurred when performing certain actions on a Ghidra project that was 
  imported from a previously exported Archive File.

__2.0.0:__
* Improved Ghidra module project starting templates for Analyzer and Plugin and added new templates
  for Loader, Exporter, and FileSystem.
* When creating a new Ghidra project, there is now an option to automatically create a Ghidra run
  configuration for the project with a customizable amount of maximum Java heap space.
* When creating a new Ghidra project, the project root directory now defaults to the workspace
  directory if a project root directory has never been set.
* When creating a new Ghidra project, the add button in the Python Support wizard page now
  automatically adds the Jython interpreter found in the Ghidra installation directory to PyDev if
  PyDev does have any Jython interpreters configured.
* A Ghidra project's dependencies that are also projects are now passed along to a launched Ghidra
  so Ghidra can discover those projects as potential modules.
* The GhidraDev popup menu is now visible from within the Project Explorer (it was previously only
  visible in the Package Explorer).
* A new page has been added to the Export Ghidra Module Extension wizard that allows the user to 
  point to a specific Gradle installation.

__1.0.2:__
* Fixed exception that occurred when performing a `Link Ghidra` on projects that specify other 
  projects on their build paths.

__1.0.1:__
* Initial Release.

## Minimum Requirements
* Eclipse 2023-12 4.30 or later
* Ghidra 11.2 or later

## Optional Requirements
* PyDev 9.3.0 or later ([more info](#pydev-support))
* Gradle - required version(s) specified by linked Ghidra release 
  ([more info](#export-ghidra-module-extension))

## Installing
GhidraDev can be installed either manually into Eclipse or automatically by Ghidra, depending on
your uses cases. The following sections outline the different procedures.

### Manual Installation in Eclipse (offline)
GhidraDev can be installed into an existing installation of Eclipse the same way most Eclipse
plugins are installed. From Eclipse:
 1. Click `Help -> Install New Software...`
 2. Click `Add...`
 3. Click `Archive...`
 4. Select GhidraDev zip file from `<GhidraInstallDir>/Extensions/Eclipse/GhidraDev/`
 5. Click `OK` (name field can be blank)
 6. Check `Ghidra` category (or `GhidraDev` entry)
 7. Click `Next`
 8. Click `Next`
 9. Accept the terms of the license agreement
10. Click `Finish`
11. Check `Unsigned` table entry
12. Click `Trust Selected`
13. Click `Restart Now`

### Manual Installation in Eclipse (online)
If you have an Internet connection, the latest GhidraDev can be installed by adding the official
[update site](https://github.com/NationalSecurityAgency/ghidra-data/raw/main/Eclipse/GhidraDev/latest)
to an existing installation of Eclipse. This has the benefit of early access to new GhidraDev 
versions before the next version of Ghidra is released, and automatic updates (if you have updates 
enabled in Eclipse). From Eclipse:
 1. Click `Help -> Install New Software...`
 2. Work with: `https://github.com/NationalSecurityAgency/ghidra-data/raw/main/Eclipse/GhidraDev/latest`
 3. Press `Enter`
 4. Check `Ghidra` category (or `GhidraDev` entry)
 5. Click `Next`
 6. Click `Next`
 7. Accept the terms of the license agreement
 8. Click `Finish`
 9. Check `Unsigned` table entry
10. Click `Trust Selected`
11. Click `Restart Now`

### Automatic Installation through Ghidra
Ghidra has the ability to launch an externally linked Eclipse when certain actions are performed,
such as choosing to edit a Ghidra script by clicking the Eclipse icon in the Ghidra Script Manager.
Ghidra requires knowledge of where Eclipse is installed before it can launch it, and will prompt the
user to enter this information if it has not been defined.  Before Ghidra attempts to launch
Eclipse, it will attempt to install GhidraDev into Eclipse's `dropins` directory if GhidraDev
is not already installed.

## GhidraDev Features
GhidraDev provides a variety of features for creating and interacting with Ghidra-related
projects in Eclipse.  GhidraDev supports creating both Ghidra script and Ghidra module projects.
Ghidra scripts are typically designed as a single Java source file that is compiled by Ghidra at
runtime and run through Ghidra's Script Manager or passed to the Headless Analyzer on the command
line for execution.  Ghidra modules are intended to represent larger, more complex features such as
Analyzers or Plugins.  When Ghidra modules are ready for production, they can be exported and
installed into Ghidra as an "extension".

#### New Ghidra Script
Opens a wizard that creates a new Ghidra script with the provided metadata in the specified 
location.  Ghidra scripts can be created in both Ghidra script and Ghidra module projects.

#### New Ghidra Script Project
Opens a wizard that creates a new Ghidra scripting project that is linked
against a specified Ghidra installation.  The project can be set up to develop scripts in both the 
user's home `ghidra_scripts` directory, as well as any scripts found in the Ghidra installation.

#### New Ghidra Module Project
Opens a wizard that creates a new Ghidra module project that is linked against a specified Ghidra
installation.  The project can be initialized with optional template source files that provide a 
good starting point for implementing advanced Ghidra features such as Analyzers, Plugins, Loaders, 
etc.

#### Import Ghidra Module Source
Opens a wizard that imports a Ghidra module source directory as a new Ghidra module project.

#### Export Ghidra Module Extension
Opens a wizard that exports a Ghidra module project as a Ghidra extension to the project's `dist` 
folder. The exported extension archive file can be distributed to other users and imported via 
Ghidra's front-end GUI. The export process requires Gradle, which is configured in the wizard. Note
that the Gradle version to use is specified in the linked Ghidra release's 
`<GhidraInstallDir>/Ghidra/application.properties` file.

#### Link Ghidra
Links a Ghidra installation to an existing Java project, which enables Ghidra script/module
development for the project. If a Ghidra installation is already linked to the project when this 
operation is performed, the project will be relinked to the specified Ghidra installation, which can
be used to build the project for a different version of Ghidra, discover new Ghidra extensions that
were later added to a Ghidra installation, or repair a corrupted project.

#### Preferences
* __Ghidra Installations:__ Add or remove Ghidra installations. Certain features such as creating
  Ghidra script/module projects require linking against a valid installation of Ghidra.
* __Script Editor:__ The port used by Ghidra to open a script in Eclipse. Must match the
  corresponding port in Ghidra's `Eclipse Integration` tool options. Disable this preference to 
  prevent GhidraDev from listening on a port for this feature.
* __Symbol Lookup:__ The project name and port used by Ghidra to perform symbol lookup in
  Eclipse. Must match the corresponding port in Ghidra's `Eclipse Integration` tool options. Disable
  this preference to prevent GhidraDev from listening on a port for this feature. Symbol lookup
  requires the Eclipse CDT plugin to be installed 
  (see [optional requirements](#optional-requirements) for supported versions).

Most GhidraDev features can also be accessed by right-clicking on appropriate project elements in
Eclipse's Project/Package Explorer. For example, the [Link Ghidra](#link-ghidra) feature can be 
accessed by right-clicking on an existing Java project, and then clicking
`Ghidra -> Link Ghidra...`.

## Launching and Debugging Ghidra
GhidraDev introduces two new run configurations to Eclipse which are capable of launching the
installation of Ghidra that an Eclipse Ghidra project is linked to:
* __Ghidra:__ Launches the Ghidra GUI.
* __Ghidra Headless:__ Launches Ghidra in headless mode. By default, this run configuration will not
  have any program arguments associated with it, which are required to tell headless Ghidra what 
  project to open, what scripts to run, etc.  Newly created `Ghidra Headless` run configurations
  will have to be modified with the desired headless program arguments. For more information on 
  headless command line arguments, see `<GhidraInstallDir>/support/analyzeHeadlessREADME.html`.

There are two ways to create Ghidra run configurations:
1. Click `Run -> Run Configurations...`
2. Right-click on `Ghidra` (or `Ghidra Headless`), and click `New`
3. In the `Main` tab, click `Browse...` and select the Ghidra project to launch
4. Optionally rename the new run configuration by editing the `Name` field at the top

Alternatively, you can right-click on any Ghidra project in the Eclipse package explorer, and then
click `Run As -> Ghidra`.

To debug Ghidra, click `Debug As -> Ghidra`. GhidraDev will automatically switch Eclipse to the 
debug perspective.

__NOTE:__ Ghidra can only be launched/debugged from an existing Eclipse Ghidra project. Launching
Ghidra from Eclipse independent of a project is not supported.

## PyDev Support
GhidraDev is able to integrate with PyDev to conveniently configure Python support into Ghidra
script and module projects. GhidraDev supports both Jython and PyGhidra Python implementations.

__NOTE:__ PyDev discontinued Jython 2 support in version 10.0.0. If you want to use GhidraDev with
Jython, you must use __PyDev 9.3.0__.  The latest vesions of PyDev support PyGhidra.

### Installing PyDev
From Eclipse:
1. Download PyDev (see [optional requirements](#optional-requirements) for supported versions)
2. Unzip PyDev
3. Click `Help -> Install New Software...`
4. Click `Add...`
5. Click `Local...`
6. Select unzipped PyDev directory
7. Click `OK` (name field can be blank)
8. Uncheck `Group items by category` (if applicable)
9. Check `PyDev for Eclipse`
10. Click `Next`
11. Click `Next`
12. Accept the terms of the license agreement
13. Click `Finish`
14. Click `Restart Now`

### Configuring PyDev
GhidraDev can add Python support to a Ghidra project when:
* Creating a new Ghidra module project
* Creating a new Ghidra script project
* Linking a Ghidra installation to an existing Java project

In order for GhidraDev to add in Python support, PyDev must have a PyGhidra or Jython interpreter 
configured. GhidraDev will present a list of detected PyGhidra/Jython interpreters that it found in 
PyDev's preferences. If no interpreters were found, one can be added from GhidraDev by clicking 
the `+` icons.

When the Jython `+` icon is clicked, GhidraDev will attempt to find the Jython interpreter bundled 
with the selected Ghidra installation and automatically configure PyDev to use it.  If for some 
reason GhidraDev was unable to find a Jython interpreter in the Ghidra installation, one will have 
to be added manually in the PyDev preferences.

When the PyGhidra `+` icon is clicked, GhidraDev will attempt to find the PyGhidra interpreter
that was last used to launch PyGhidra.  If it cannot find it, you will have to launch PyGhidra
and try again.

## Upgrading
GhidraDev is upgraded differently depending on how it was installed.  If GhidraDev was
[manually installed in Eclipse](#manual-installation-in-eclipse), it can be upgraded the same was it
was installed.

If GhidraDev was [automatically installed through Ghidra](#automatic-installation-through-ghidra), 
it can be upgraded by simply removing the GhidraDev file from Eclipse's `dropins` directory before
following one of the two techniques described in the [Installing](#installing) section.

## Uninstalling
GhidraDev is uninstalled differently depending on how it was installed. If GhidraDev was
[manually installed in Eclipse](#manual-installation-in-eclipse), it can be uninstalled as follows
from Eclipse:
1. Click `Help -> About Eclipse`
    * For macOS: `Eclipse -> About Eclipse`
2. Click `Installation Details`
3. Select `GhidraDev`
4. Click `Uninstall...`
5. Select `GhidraDev`
6. Click `Finish`
7. Click `Restart Now`

If GhidraDev was [automatically installed through Ghidra](#automatic-installation-through-ghidra), 
it can be uninstalled by simply removing the GhidraDev file from Eclipse's `dropins` directory and
restarting Eclipse.  The `dropins` directory can be found at the top level of Eclipse's
installation directory.

## Frequently Asked Questions
* __I've created a Ghidra script project. Where should I create my new scripts?__
    * The best place to create your scripts in is your home `~/ghidra_scripts` directory because 
      Ghidra will automatically find them there without any additional configuration. By default,
      your Ghidra script project will have a folder named `Home scripts` which is linked to your 
      home `~/ghidra_scripts` directory. Either right-click on this folder in Eclipse and do 
      `GhidraDev -> New -> GhidraScript...` or from the menu bar do `GhidraDev -> New -> 
      GhidraScript...` and populate the `Script folder` box with your project's `Home scripts` 
      folder.
* __How do I launch Ghidra in headless mode from Eclipse?__
    * GhidraDev provides custom run configurations to launch Ghidra installations both in GUI mode
      and headlessly.  See the [Launching](#launching-and-debugging-ghidra) section for information
      on how to launch Ghidra from Eclipse.
* __Why doesn't my Ghidra module project know about the Ghidra extension I installed into my Ghidra
  installation?__
    * You most likely installed the Ghidra extension after the Ghidra installation was linked
      to your Ghidra module project, which automatically happens when the project is created.
      Simply [relink](#link-ghidra) your Ghidra installation to the project, and your project will 
      pick up any newly discovered Ghidra extensions.

## Additional Resources
For more information on the GhidraDev plugin and developing for Ghidra in an Eclipse environment,
please see the __Ghidra Scripting slide deck__
at `<GhidraInstallDir>/docs/GhidraClass/Intermediate/Scripting.html`.

## Building
GhidraDev is currently built from Eclipse and distributed with Ghidra manually. Ideally we will use
Gradle one day, but we aren't there yet. We do rely on Gradle to generate the Eclipse project and 
build GhidraDev's dependencies though.

__NOTE:__ Only "Eclipse for RCP and RAP Developers" has the ability to do the below instructions. 
The following instructions assume that you are using this version of Eclipse.

#### Importing GhidraDev Eclipse projects (they are deactivated by default):
1. Run `gradle prepGhidraDev eclipse -PeclipsePDE`
2. From Eclipse, `File -> Import -> General -> Existing Projects into Workspace`
3. From the ghidra repo, import `Eclipse GhidraDevFeature` and `Eclipse GhidraDevPlugin`

#### Changing version number (GhidraDev is versioned independently of Ghidra):
1. Open `plugin.xml` in the GhidraDevPlugin project
2. In the `Overview` tab, update the `Version` field to `x.y.z.qualifier` and save
3. Open `feature.xml`in the `GhidraDevFeature` project
4. In the `Overview` tab, update the `Version` field to `x.y.z.qualifier` and save
5. Open `category.xml` in the `GhidraDevFeature` project
6. Highlight `ghidra.ghidradev (x.y.z.qualifier)`, and click `Remove`
7. Highlight `ghidra.ghidradev` and click `Add Feature`
8. Select `ghidra.ghidradev (x.y.z.qualifer)`, click `OK`, and save
9. Update the [Change History](#change-history) section if necessary

#### Building from Eclipse:
1. Do a `gradle prepDev` to ensure GhidraDev's dependencies are up-to-date
2. `File -> Export -> Plug-in Development -> Deployable features`
3. Check `ghidra.ghidradev (x.y.z.qualifier)`
4. Select `Archive file` and choose a directory to save it to. Name it `GhidraDev-x.y.z.zip`.
5. In the `Options` tab make sure things look like this:
    * Export source: UNCHECKED
    * Package as individual JAR archives: CHECKED
    * Generate p2 repository: CHECKED
    * Categorize repository: CHECKED + Browse to category.xml file in the GhidraDevFeature project
    * Qualifier replacement: CHECKED + clear field so default is used
    * Save as Ant script: UNCHECKED
    * Allow for binary cycles in target platform: CHECKED
    * Use class files compiled in the workspace: UNCHECKED
6. Finish
