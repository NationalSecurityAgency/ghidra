# Headless Analyzer README

## Table of Contents
1. [Introduction](#introduction)
2. [Usage](#usage)
3. [Examples](#examples)
4. [Scripting](#scripting)
   * [Passing Parameters using arguments](#passing-parameters-using-arguments)
   * [Passing Parameters using `askXxx()` methods](#passing-parameters-using-askxxx-methods)
   * [Headless Scripts](#headless-scripts)
     * [Enabling/Disabling Analysis](#enablingdisabling-analysis)
     * [Setting the Import Directory](#setting-the-import-directory)
     * [Checking for Analysis Timeout](#checking-for-analysis-timeout)
     * [Passing Values Between Scripts](#passing-values-between-scripts)
     * [Using Scripts to Control Program Disposition][headlessdispo] 
     * [Using Multiple Scripts to Control Program Disposition][headlessdispomulti]
5. [Wildcards](#wildcards)

## Introduction
The Headless Analyzer is a command-line-based (non-GUI) version of Ghidra that allows users to:
* Create and populate projects
* Perform analysis on imported or existing binaries
* Run non-GUI scripts in a project (scripts may be program-dependent or program-independent)

The Headless Analyzer can be useful when performing repetitive tasks on a project (i.e., importing 
and analyzing a directory of files or running a script over all the binaries in a project).

Users initiate Headless operation using the `analyzeHeadless` shell script. 
The shell script takes, at a minimum, the path and name of an existing project (or one to be 
created). When other parameters are specified, the following types of actions may be performed:

* [Import][import] a single file or directory of executable(s) (recursively or non-recursively).
* [Process][process] a single file or directory of executable(s) already present in an existing 
  project (recursively or non-recursively).
* Run any number of non-GUI Ghidra [pre-processing scripts][prescript] on each executable.
* Turn analysis on or [off][noanalysis] for each executable.
* Run any number of non-GUI Ghidra [post-processing scripts][postscript] on each executable.
* Write to a [log][log] with information about each file processed. [Separated logging][scriptlog]
  is available for scripts.
* Keep or [delete][deleteproject] a created project.
* Save any changes made to the project/file, or operate in a [read-only][readonly] manner in 
  [`-import`][import] or [`-process`][process] modes.
* Use pre- and/or post-processing scripts to dictate [program disposition][headlessdispomulti]. For
  example, scripts can dictate whether further processing (i.e., analysis or other scripts) should 
  be aborted and whether the current file should be deleted after all processing is complete.

While running, be aware that:
* The Headless Analyzer may not run if the specified project is already open in Ghidra.
* In bulk import mode (i.e., specifying a directory, `-import dirOfExes`, or wildcard string, 
  `-import dir1/*`), any file beginning with the character `.` is assumed to be a hidden file and 
  ignored by default. However, when a file beginning with `.` is named during import (for example, 
  `import /Users/user/.hidden.exe`), the Headless Analyzer will attempt to import it.
* Log files can only be redirected if Log4J is used.

## Usage
The Headless Analyzer uses the command-line parameters discussed below. See [Examples](#examples) 
for common use cases.

<pre>
    analyzeHeadless <a href="#project_location">&lt;project_location&gt;</a> &lt;<a href="#project_namefolder_path">project_name&gt;[/&lt;folder_path&gt;]</a> | <a href="#ghidraserverportrepository_namefolder_path">ghidra://&lt;server&gt;[:&lt;port&gt;]/&lt;repository_name&gt;[/&lt;folder_path&gt;]</a>
        [[<a href="#-import-directoryfile">-import [&lt;directory&gt;|&lt;file&gt;]+</a>] | [<a href="#-process-project_file">-process [&lt;project_file&gt;]]</a>]
        [<a href="#-prescript-scriptnameext-arg">-preScript &lt;ScriptName&gt;&nbsp;[&lt;arg&gt;]*</a>]
        [<a href="#-postscript-scriptnameext-arg">-postScript &lt;ScriptName&gt;&nbsp[&lt;arg&gt;]*</a>]
        [<a href="#-scriptpath-path1path2">-scriptPath &quot;&lt;path1&gt;[;&lt;path2&gt;...]&quot;</a>]
        [<a href="#-propertiespath-path1path2">-propertiesPath &quot;&lt;path1&gt;[;&lt;path2&gt;...]&quot;</a>]
        [<a href="#-scriptlog-path-to-script-log-file">-scriptlog &lt;path to script log file&gt;</a>]
        [<a href="#-log-path-to-log-file">-log &lt;path to log file&gt;</a>]
        [<a href="#-overwrite">-overwrite</a>]
        [<a href="#-recursive-depth">-recursive [&lt;depth&gt;]</a>]
        [<a href="#-readonly">-readOnly</a>]
        [<a href="#-deleteproject">-deleteProject</a>]
        [<a href="#-noanalysis">-noanalysis</a>]
        [<a href="#-processor-languageid">-processor &lt;languageID&gt;</a>]
        [<a href="#-cspec-compilerspecid">-cspec &lt;compilerSpecID&gt;</a>]
        [<a href="#-analysistimeoutperfile-timeout-in-seconds">-analysisTimeoutPerFile &lt;timeout in seconds&gt;</a>]
        [<a href="#-keystore-keystorepath">-keystore &lt;KeystorePath&gt;</a>]
        [<a href="#-connect-userid">-connect [&lt;userID&gt;]</a>]
        [<a href="#-p">-p</a>]
        [<a href="#-commit-comment">-commit [&quot;&lt;comment&gt;&quot;]</a>]
        [<a href="#-oktodelete">-okToDelete</a>]
        [<a href="#-max-cpu-max-cpu-cores-to-use">-max-cpu &lt;max cpu cores to use&gt;</a>]
        [<a href="#-librarysearchpaths-path1path2">-librarySearchPaths &lt;path1&gt;[;&lt;path2&gt;...]</a>]
        [<a href="#-loader-desired-loader-name">-loader &lt;desired loader name&gt;</a>]
        [<a href="#-loader-desired-loader-name">-loader-&lt;loader argument name&gt; &lt;loader argument value&gt;</a>]
</pre>

### `<project_location>`
The directory that either contains an existing Ghidra project (in [`-import`][import] or 
[`-process`][process] mode) or will contain a newly created project (in [`-import`][import] mode for
a local project).
  
___You must specify either a project location and project name, or a Ghidra Server repository URL.___
  
Some parameters will have no effect, depending on which `project_location` is specified. The 
following table shows parameters that are specific to `project_location`:

| Parameter | Local Project | Server Repository |
| --------- | ------------- | ----------------- |
| -p        |               |         X         |
| -connect  |               |         X         |
| -keystore |               |         X         |
| -commit   |               |         X         |
| -delete   |      X        |                   |


### `<project_name>[/<folder_path>]`
The name of either an existing project (in [`-import`][import] or [`-process`][process] mode) or new
project (in [`-import`][import] mode) to be created in the above directory. If the optional folder
path is included, imports will be rooted under this project folder. In [`-import`][import] mode with
[`-recursive`][recursive] enabled, any folders in the folder path that do not already exist in the 
project will be created (even if nested).

___You must specify either a project location and project name, or a Ghidra Server repository URL.___

### `ghidra://<server>[:<port>]/<repository_name>[/<folder_path>]`
A Ghidra Server repository URL (shared Ghidra Server project) and folder path. Using the repository
URL eliminates the need for a local shared Ghidra project; however, the named repository must 
already exist on the Ghidra Server. If the specified repository does not already exist, it will not 
be created (see the `GhidraProject` class for a simple API that allows shared project creation from 
within a script).

If the optional folder path is included, imports will be rooted under this folder (in 
[`-import`][import] mode, folders will be created if they do not already exist).

### `-import [<directory>|<file>]+`
_Note: [`-import`][import] and [`-process`][process] can not both be present in the parameters list._

Specifies one or more executables (or directories of executables) to import. When importing a 
directory or supported container format, a folder with the same name will be created in the Ghidra
project. When using the [`-recursive`][recursive] parameter, each executable that is found in a
recursive search through the given directory or container file will be stored in the project in the 
same relative location (i.e., any directories found under the import directory will also be created
in the project).

Operating system-specific wildcard characters can be used when importing files and/or directories. 
Please see the [Wildcards](#wildcards) section for more details.

When importing multiple executables/directories in the same session, use one of the following 
methods:
* List multiple directories and/or executables after the [`-import`][import] option, separated by a 
  space.
  ```bash
  -import /Users/myDir/peFiles /Users/myDir/otherFiles/test.exe
  ```
* Repeat the [`-import`][import] option multiple times (each use of [`-import`][import] may be 
  separated by other parameters) to import from more than one directory or file source.
  ```bash
  -import /Users/myDir/peFiles -recursive -import /Users/myDir/otherFiles/test.exe
  ``` 

### `-process [<project_file>]`
_Note: [`-import`][import] and [`-process`][process] can not both be present in the parameters list._

Performs processing (running pre/post-scripts and/or analysis) on one or more program files
that already exist in the project or repository. Use the optional `project_file` argument to specify
an existing file by name.  Searching will be performed within the specified project folder 
(specified by `folder_path`, which was included with the [project_name][projectname] or 
[repository URL][ghidraserver] specification). Omit the `project_file` argument to allow processing
over all files within the project folder.

You can also use the wildcard characters `*` and `?` in the `project_file` parameter to specify all 
files within a folder which match the pattern. To prevent premature expansion (by the shell) of any 
wildcard characters, use single quotes around the `project_file`. For example:
```bash
-process '*.exe'
```
For further details on wildcard usage, please see the [Wildcards](#wildcards) section 
below.

Omitting the optional `project_file` argument will cause all files to be processed within the 
project folder (equivelent to `*`).

Including the [`-recursive`][recursive] parameter will cause the same project file name/pattern 
search to be performed recursively within all sub-folders.  

Unlike the [`-import`][import] option, [`-process`][process] may only be specified once.

### `-preScript <ScriptName.ext> [<arg>]*`
Identifies the name of a script that will execute before analysis, and an optional list of arguments
to pass to the script. The script name must include its file extension (i.e., _MyScript.java_).

___This parameter expects the script name only; do not include the path to the script.___ The
Headless Analyzer searches specific default locations for the named script, but additional script 
director(ies) may also be specified (see the [`-scriptPath`][scriptpath] argument for more 
information).

This option must be repeated to specify additional scripts. See the [Scripting](#scripting) section
for a description of advanced scripting capabilities.

### `-postScript <ScriptName.ext> [<arg>]*`
Identifies the name of a script that will execute after analysis, and an optional list of arguments
to pass to the script. The script name must include its file extension (i.e., _MyScript.java_).

___This parameter expects the script name only; do not include the path to the script.___ The
Headless Analyzer searches specific default locations for the named script, but additional script 
director(ies) may also be specified (see the [`-scriptPath`][scriptpath] argument for more 
information).

This option must be repeated to specify additional scripts. See the [Scripting](#scripting) section
for a description of advanced scripting capabilities.

### `-scriptPath "<path1>[;<path2>...]"`
Specifies the search path(s) for scripts, including secondary scripts (a script invoked from 
another script). A path may start with `$GHIDRA_HOME`, which corresponds to the Ghidra installation
directory, or `$USER_HOME`, which corresponds to the user's home directory. On Unix systems, these 
home variables must be escaped using a `\` (backslash) character.

Examples:
* Windows:
  ```bat
  -scriptPath "$GHIDRA_HOME/Ghidra/Features/Base/ghidra_scripts;/myscripts"
  ```
* Unix:
  ```bash
  -scriptPath "\$GHIDRA_HOME/Ghidra/Features/Base/ghidra_scripts;/myscripts"
  ```

The `scriptPath` parameter is optional. If it is not present, the Headless Analyzer will search the 
following paths for the specified script(s):
* `$USER_HOME/ghidra_scripts`
* All `ghidra_script` subdirectories that exist in the Ghidra distribution

### `-propertiesPath "<path1>[;<path2>...]"`
Specifies path(s) that contain _.properties_ files used by scripts or secondary/subscripts. A path 
may start with `$GHIDRA_HOME`, which corresponds to the Ghidra installation directory, or 
`$USER_HOME`, which corresponds to the user's home directory. On Unix systems these home variables 
must be escaped with a `;` character.

More information on the use of _.properties_ files to pass parameters during Headless Analysis can 
be found [here](#passing-parameters-using-askxxx-methods).

### `-scriptlog <path to script log file>`
Sets the location of the file that stores logging information from pre- and post-scripts. If a 
path to a script log file is not set, script logs are written to `script.log` in the user directory,
by default.

Note: Only the built-in scripting print methods will print to the script log file (`print`, 
`println`, `printf`, `printerr`).

Also note that in Python scripts, `print` writes to `stdout`.  To write to the log from Python, use
`println` instead.

### `-log <path to log file>`
Sets the location of the file that stores logging information from analysis or other non-script 
processing of the files. If a path to a log file is not set, logging information is written to 
`application.log` in the user directory, by default.

### `-overwrite`
Applies to [-import][import] mode only and is ignored if the [`-readOnly`][readonly] option is 
present. If present, an existing project file that conflicts with an import file is overwritten. 
If this parameter is not included, import files that conflict with existing project files will be 
skipped (if not operating with the [`-readOnly`][readonly] option). If a conflicting file is 
contained within a version repository, and the [`-commit`][commit] option has not been specified, 
the overwrite will fail.  Removing a versioned file is also subject to other permission and in-use 
restrictions which could also cause an overwrite failure.

### `-recursive [<depth>]`
If present, enables recursive descent into directories and project sub-folders when a directory/
folder has been specified in [`-import`][import] or [`-process`][process] modes.

Specifying a positive integer value for the optional `<depth>` argument enables recursive descent 
into supported container files (e.g., zip, tar, .a, etc). The depth value only applies to nested 
container files. Intermediate directories found within each nested container file are not affected 
by the specified depth value.  If a depth value is not specified, it will default to 0 if importing 
a directory, and 1 if importing a file.  A depth of 0 will prevent recursing into any container 
files.

### `-readOnly`
If present in [`-import`][import] mode, imported files will NOT be saved to the project. If present
in [`-process`][process] mode, any changes made to existing files by scripts or analysis are 
discarded.  When processing a shared project or URL associated with a read-only repository, such 
files will be skipped unless this option is specified. The [`-overwrite`][overwrite] option will be 
ignored if this option is specified  during import operations.

### `-deleteProject`
If present, the Ghidra project will be deleted after scripts and/or analysis have completed 
(only applies if the project has been created in the current session with 
[`-import`][import]; existing projects are never deleted). This project delete option is assumed 
when the [`-readOnly`][readonly] option is specified for import operations which create a new 
project.

### `-noanalysis`
If present, executables will not be analyzed (auto-analysis occurs by default).

### `-processor <languageID>`
Specifies the processor information to be used in [`-import`][import] mode (and subsequent analysis,
if analysis is enabled). Be sure to use quotes around the `languageId` if it contains spaces. If 
this parameter is not present, Ghidra uses header info (if available) to identify the processor.

The possible _languageIDs_ can be found in the processor-specific _.ldefs_ files (found here: 
`ghidra_x.x\Ghidra\Processors\proc_name\data\languages\*.ldefs`) in the `id` attribute of the 
`language` element. The specified `<languageID>` should match exactly, including case, as it appears
in the _.ldefs_ file.

For example:
```xml
<language processor="x86"
            endian="little"
            size="32"
            variant="default"
            version="2.6"
            slafile="x86.sla"
            processorspec="x86.pspec"
            manualindexfile="../manuals/x86.idx"
            id="x86:LE:32:default">
```

_Note: The [`-processor`][processor] parameter may be used without specifying the [`-cspec`][cspec] 
parameter (if the given processor is valid, the Headless Analyzer chooses the default compiler 
specification for that processor)._

### `-cspec <compilerSpecID>`
Specifies the compiler specification to be used in [`-import`][import] mode (and subsequent 
analysis, if analysis is enabled).

The possible _compilerSpecIDs_ can be found in the processor-specific _.ldefs_ files (found here: 
`ghidra_x.x\Ghidra\Processors\proc_name\data\languages\*.ldefs`) in the `id` attribute of the 
appropriate `compiler` element. The specified `<compilerSpecID>` should match exactly, including 
case, as it appears in the _.ldefs_ file.

For example:
```xml
<compiler name="Visual Studio" spec="x86win.cspec" id="windows"/>
<compiler name="gcc" spec="x86gcc.cspec" id="gcc"/>
<compiler name="Borland C++" spec="x86borland.cspec" id="borlandcpp"/>
```

_Note: The [`-cspec`][cspec] parameter may __not__ be used without specifying the 
[`-processor`][processor] parameter._

### `-analysisTimeoutPerFile <timeout in seconds>`
Sets a timeout value (in seconds) for analysis. If analysis on a file exceeds the specified time, 
analysis is interrupted and processing continues as scheduled (i.e., to the 
[`-postScript`][postscript] stage, if specified). Results from individual analyzers that have 
completed processing prior to timeout will still be saved with the program. Post-scripts can be used
to detect that analysis has timed out (in Headless processing ONLY) by calling the 
`getHeadlessAnalysisTimeoutStatus()` method. 

### `-keystore <KeystorePath>`
When connecting to a Ghidra Server using PKI or SSH authentication, this option allows 
specification of a suitable private keystore file. The keystore file should always be properly 
protected with filesystem protections. Since SSH authentication is intended for batch operations, 
we do not support password protected SSH keys. However, we do support password prompting for 
PKI authentication.

[See here for more information regarding which authentication method to use](#authentication).

### `-connect <userID>`
If used, allows the process owner's default userID to be overridden with the given `userID` when 
connecting to a Ghidra Server. In order to use this parameter, the server must be configured to 
allow a non-default username (Ghidra server `-u` option).

### `-p`
This option may be specified to allow for interactive password prompting when either a specified
PKI keystore is password protected or the Ghidra Server requires password authentication. 
This option should not be used during batch operations where a user will be unable to enter a 
password. __If the terminal in use is unable to suppress echoing an entered password, a warning will
be issued with the prompt, and the entered password will be echoed to the terminal. Use of this 
option is discouraged when such a warning occurs.__

[See here for more information regarding which authentication method to use](#authentication).

### `-commit ["<comment>"]`
When connected to a shared project, enables a commit of changes to the project's underlying 
repository (residing on the Ghidra Server). Commits are enabled by default for shared projects; 
however, the optional quoted `comment` may be specified and will be saved with all commits. Commits
do not apply when the [-readOnly][readonly] parameter is present.

### `-okToDelete`
When using Headless Scripts to control [program disposition][headlessdispo] in [`-process`][process]
mode, it is possible to delete existing programs in a project. These deletions are permanent and can
not be undone (in a versioned project, all versions of a program are deleted). To ensure that 
programs are not deleted irretrievably without the user's knowledge, Headless operation requires the
[`-okToDelete`][oktodelete] parameter to be set if a program is to be deleted in 
[`-process`][process] mode. If a program is scheduled to be deleted and [`-okToDelete`][oktodelete]
has not been set, Headless will print a warning and the program will not be deleted.

The [`-okToDelete`][oktodelete] parameter is not necessary when running in [`-import`][import]
mode. If a HeadlessScripts schedules deletion of one of the programs being imported, the program 
will simply not be saved to the project.

### `-max-cpu <max cpu cores to use>`
Sets the maximum number of CPU cores to use during headless processing (must be an integer). 
Setting `max-cpu` to 0 or a negative integer is equivalent to setting the maximum number of cores to
1.

### `-librarySearchPaths <path1>[;<path2>...]`
Specifies an ordered list of library search paths to use during import instead of the default. 
Search paths may be either full system paths or "FSRLs".

### `-loader <desired loader name>`
Forces the file to be imported using a specific loader.

Loaders can take additional arguments that they apply during the import process. Below is a list of
the most commonly used loaders and their arguments.

__Note:__ Full java package loader paths are no longer recognized.

* `-loader BinaryLoader`
  * `-loader-blockName <block name>`
  * `-loader-baseAddr <base address>`[^1]
  * `-loader-fileOffset <file offset>`[^2]
  * `-loader-length <length in bytes>`[^2]
  * `-loader-applyLabels <true|false>`
  * `-loader-anchorLabels <true|false>`

* `-loader ElfLoader`
  * `-loader-applyLabels <true|false>`
  * `-loader-anchorLabels <true|false>`
  * `-loader-linkExistingProjectLibraries <true|false>`
  * `-loader-projectLibrarySearchFolder <project path>`
  * `-loader-loadLibraries <true|false>`
  * `-loader-libraryLoadDepth <depth>`
  * `-loader-libraryDestinationFolder <project path>`
  * `-loader-applyRelocations <true|false>`
  * `-loader-applyUndefinedData <true|false>`
  * `-loader-imagebase <imagebase>`[^3]
  * `-loader-dataImageBase <dataImageBase>`[^4]
  * `-loader-includeOtherBlocks <true|false>`
  * `-loader-maxSegmentDiscardSize <0..255> (default: 255)`

* `-loader PeLoader`
  * `-loader-applyLabels <true|false>`
  * `-loader-anchorLabels <true|false>`
  * `-loader-linkExistingProjectLibraries <true|false>`
  * `-loader-projectLibrarySearchFolder <project path>`
  * `-loader-loadLibraries <true|false>`
  * `-loader-libraryLoadDepth <depth>`
  * `-loader-libraryDestinationFolder <project path>`
  * `-loader-ordinalLookup <true|false>`
  * `-loader-parseCliHeaders <true|false>`
  * `-loader-showDebugLineNumbers <true|false>` 

* `-loader MachoLoader`
  * `-loader-applyLabels <true|false>`
  * `-loader-anchorLabels <true|false>`
  * `-loader-linkExistingProjectLibraries <true|false>`
  * `-loader-projectLibrarySearchFolder <project path>`
  * `-loader-loadLibraries <true|false>`
  * `-loader-libraryLoadDepth <depth>`
  * `-loader-libraryDestinationFolder <project path>`
  * `-loader-reexport <true|false>`

## Authentication
Use this table to figure out which authentication option to use with the Headless Analyzer, based on
your Ghidra Server's method of authentication, and the type of analysis operation you are 
performing.

| Type of Operation        | SSH Without Password* | SSH With Password | PKI Without Password  | PKI With Password                        | Username/Password |
| ------------------------ | --------------------- | ----------------- | --------------------- | ---------------------------------------- | ----------------- |
| Interactive Command Line | [-keystore][keystore] | Not Supported     | [-keystore][keystore] | [-keystore][keystore] and [-p][password] | [-p][password]    |
| Batch/Script Use         | [-keystore][keystore] | Not Supported     | [-keystore][keystore] | Not Supported                            | NotSupported      |

__*NOTE:__ The use of OpenSSH keys are not supported. The following command can be used to generate
a suitable SSH key while avoiding the unsupported OpenSSH format: `ssh-keygen -b 2048 -t rsa -m pem`

## Examples

#### Example 1
Import a binary `/binaries/binary1.exe` to a local Ghidra Project named `Project1`. Analysis is on 
by default.
```bash
analyzeHeadless /Users/user/ghidra/projects Project1 -import /binaries/binary1.exe
```
----------------------------------------------------------------------------------------------------
#### Example 2
Import all `*.exe` binaries from a local folder to a local Ghidra project named `Project1`, 
suppressing analysis.
```bash
analyzeHeadless /Users/user/ghidra/projects Project1 -import /Users/user/sourceFiles/*.exe -noanalysis
```
----------------------------------------------------------------------------------------------------
#### Example 3
Import the binary `/usr/local/binaries/binaryA.exe` to a subfolder of a local Ghidra Project, 
running a prescript, but suppressing analysis.
```bash
analyzeHeadless /Users/user/ghidra/projects Project1/folderOne -scriptPath /usr/scripts -preScript RunThisScriptFirst.java -import /usr/local/binaries/binaryA.exe -noanalysis
```
----------------------------------------------------------------------------------------------------
#### Example 4
Import the binary `/usr/local/binaries/binaryB.exe` to a local Ghidra Project, running a prescript 
that depends on a _.properties_ file in the location `/propertiesLocation`. Analysis is on by 
default.
```bash
analyzeHeadless /Users/user/ghidra/projects Project1 -scriptPath /usr/scripts -preScript RunThisScriptFirst.java -propertiesPath /propertiesLocation -import /usr/local/binaries/binaryB.exe
```
----------------------------------------------------------------------------------------------------
#### Example 5
Specify more than one import to a local project, running more than one script and performing
analysis.
```bash
analyzeHeadless /Users/user/ghidra/Projects Project1/folderOne -scriptPath /usr/scripts -preScript RunThisScriptFirst.java -preScript RunThisScriptSecond.java -import /usr/local/binaries/binaryA.exe /user/local/morebinaries -postScript RunThisScriptLast.java
```
OR
```bash
analyzeHeadless /Users/user/ghidra/Projects Project1/folderOne -scriptPath /usr/scripts -preScript RunThisScriptFirst.java -preScript RunThisScriptSecond.java -import /usr/local/binaries/binaryA.exe -postScript RunThisScriptLast.java -import /user/local/morebinaries
```
----------------------------------------------------------------------------------------------------
#### Example 6
Run a script on an existing project binary `importedBinA.exe` in the folder `folderOne` of the 
existing project named `Project1`.
```bash
analyzeHeadless /Users/user/ghidra/Projects Project1/folderOne -scriptPath /user/scripts -postScript FixupScript.java -process importedBinA.exe -noanalysis
```
----------------------------------------------------------------------------------------------------
#### Example 7
Recursively run scripts and analysis over all the binaries in the folder `folderTwo` of the existing
project named `Project2`.
```bash
analyzeHeadless /Users/user/ghidra/Projects Project2/folderTwo -scriptPath /user/scripts -preScript FixupPreScript.java -process -recursive
```
----------------------------------------------------------------------------------------------------
#### Example 8
Run a script and analysis on binaries starting with the letter `a` in the folder `aFolder` (and any 
of its subfolders) in the existing projected named `Project1`.
```bash
analyzeHeadless /Users/user/ghidra/Projects Project1/aFolder -scriptPath /user/scripts -preScript ProcessAScript.java -process 'a*' -recursive
```
----------------------------------------------------------------------------------------------------
#### Example 9
Recursively import the directory `/usr/local/binaries` to a Ghidra Server, running a prescript and 
analysis. Commit changes with the specified comment. Server prompts for a password for the user 
named `userID`.
```bash
analyzeHeadless ghidra://example.server.org:13100/RepositoryName/RootFolder -scriptPath /usr/scripts/ -preScript RunThisScriptFirst.java -import /usr/local/binaries -recursive -connect userID -p -commit "Testing server imports."
```
----------------------------------------------------------------------------------------------------
#### Example 10
Change the default log location when importing and analyzing a file.
```bash
analyzeHeadless /Users/user/ghidra/projects Project1 -import /binaries/binary1.exe -log /new/log_location.txt
```
----------------------------------------------------------------------------------------------------
#### Example 11
Re-import and overwrite a file that already exists in the project.
```bash
analyzeHeadless /Users/user/ghidra/projects Project1 -import /binaries/IAlreadyExist.exe -overwrite
```
----------------------------------------------------------------------------------------------------
#### Example 12
Create a new project, import and analyze a file, then delete the project when done.
```bash
analyzeHeadless /Users/user/ghidra/projects ANewProject -import /binaries/binary2.exe -deleteProject
```
----------------------------------------------------------------------------------------------------
#### Example 13
Set a timeout value, in seconds, for analysis (analysis will abort if it takes longer than the set
timeout value).
```bash
analyzeHeadless /Users/user/ghidra/projects MyProject -import /binaries/binary2.exe -analysisTimeoutPerFile 100
```
----------------------------------------------------------------------------------------------------
#### Example 14
Run a script without using `-import` or `-process` modes (___Script must not be program-dependent!___).
```bash
analyzeHeadless /Users/user/ghidra/projects MyProject -preScript HelloWorldScript.java -scriptPath /my/ghidra_scripts
```
----------------------------------------------------------------------------------------------------
#### Example 15
Specify a language and compiler to be used when importing with analysis.
```bash
analyzeHeadless /Users/user/ghidra/projects MyProject -import hello.exe -processor "x86:LE:32:System Management Mode" -cspec default
```
----------------------------------------------------------------------------------------------------
#### Example 16
Import, run a script, and analyze a file, but don't allow the file to be saved to the project.
```bash
analyzeHeadless /Users/user/ghidra/projects MyProject -import hello.exe -preScript GetInfoScript.java -readOnly
```
----------------------------------------------------------------------------------------------------
#### Example 17
Import and run scripts that take their own arguments.
```bash
analyzeHeadless /Users/user/ghidra/projects MyProject -import hello.exe -preScript Script.java arg1 arg2 arg3 -preScript AnotherScript.java "arg1 with spaces" arg2
```
----------------------------------------------------------------------------------------------------
#### Example 18
Import a PE file as a raw binary image with a specified base address and block name.
```bash
analyzeHeadless /Users/user/ghidra/projects MyProject -import hello.exe -loader BinaryLoader -loader-baseAddr 0x1000 -loader-blockName MyBlock -processor x86:LE:32:default
```
----------------------------------------------------------------------------------------------------

## Scripting
Many scripts that extend the _GhidraScript_ class, and written for use with the headed (GUI) version
of Ghidra, can also be used during Headless operation. However, there are certain GUI-specific 
methods that do not make sense when called during Headless operation. When a GhidraScript containing
one or more GUI-specific methods is run headlessly, the script will throw an `ImproperUseException`.

A script that extends the _HeadlessScript_ class may be used to write scripts that refer to 
Headless-only methods. See the [Headless Scripts](#headless-scripts) section for more detail.

Here are some general guidelines for running scripts headlessly.
* If neither [`-import`][import] mode nor [`-process`][process] mode is specified in the Headless 
  Analyzer command line arguments, only the specified pre/post-script(s) will be executed. In this
  case, all scripts must execute in a program-independent manner, or errors will occur. If you 
  intend for scripts to be run against programs, please run in [`-process`][process] mode.
* For each pre-/post-script group, scripts are executed in the order specified on the command line.
* Any pre- or post-script may invoke the `setTemporary()` method on `currentProgram` to prevent 
  changes from being saved. In [`-import`][import] mode, the method prevents the specific import 
  from being saved. In [`-process`][process] mode, the method prevents changes to the program from 
  being saved.
* Avoid using the script API method `setServerCredentials()` for shared projects.

### Passing Parameters using arguments
As of Ghidra 7.2, it is possible to pass script-specific arguments directly to scripts. The 
arguments are stored in a String array and can be accessed with the following method:
```java
String[] args = getScriptArgs();
```
If running in headless mode, this array will contain the ordered list of arguments passed to the 
script on the command line (specified with [`-preScript`][prescript] or
[`-postScript`][postScript]).

For example, if a script was run with the following command:
```bash
analyzeHeadless /Users/user/ghidra/projects MyProject -import hello.exe -preScript Script.java arg1 arg2 arg3 -preScript AnotherScript.java "arg1 with spaces" arg2
```
Then the elements of the argument array for _Script.java_ would look like this:
```java
args = {"arg1", "arg2", "arg3"}
```
and the argument array for _AnotherScript.java_ would look like this:
```java
args = {"arg1 with spaces", "arg2"}
```

### Passing Parameters using `askXxx()` methods
Many of the GhidraScript `askXxx()` methods can be run in both headless and headed (GUI) modes, 
allowing seamless script usage between headed and headless modes. As of Ghidra 6.1, the following 
methods can be run in both modes:
* `askFile`
* `askDirectory`
* `askLanguage`
* `askProjectFolder`
* `askInt`
* `askLong`
* `askAddress`
* `askBytes`
* `askProgram`
* `askDomainFile`
* `askDouble`
* `askString`
* `askChoice`
* `askChoices`
* `askYesNo`

_Further details for each specific `askXxx()` method can be found in the method's JavaDoc._

When running headlessly, the `askXxx()` methods allow users to "pre-set" or "pass in" one or more
values for use in scripts. Use the appropriate method to pass in values of certain types (i.e., 
file, directory, int, long).

To pass a value to a script, create a _.properties_ file corresponding to each GhidraScript that 
uses an `askXxx()` method. For example, the _.properties_ file that corresponds to a script named 
_MyScript.java_ would share the script's basename and be called _MyScript.properties_. By default, 
the Headless Analyzer assumes that the script and its _.properties_ file are both located in the 
same folder. If you would like the _.properties_ file to be in a different location from the script,
you can use the [`-propertiesPath`][propertiespath] parameter to specify the location of the 
_.properties_ file. Below is an example of a GhidraScript and its _.properties_ file. Use it for 
reference to determine how the _.properties_ file should be structured to communicate the necessary
information to the GhidraScript:

___Script1.java___
```java
public class Script1 extends GhidraScript {
 
    @Override
    public void run() throws Exception {
  	
        File userFile = askFile("Choose a file ", "Please choose a file: ");
        println("Chosen file: " + userFile.toString());

        double userDouble = askDouble("Double dialog", "Please enter a double: ");
        println("Entered double: " + userDouble);
	
        double userDouble2 = askDouble("Double dialog", "Please enter another double: ");
        println("Second entered double: " + userDouble2);

        Address userAddress = askAddress("Address", "Enter an address!");
        println("Entered address: " + userAddress.toString());

        byte[] userBytes = askBytes("Asking for bytes", "Put some bytes here --");
        StringBuilder byteStr = new StringBuilder();
        for (byte aByte : askedBytes) {
            byteStr.append(String.format("%02X ", aByte));
        }
        println("Bytes: " + byteStr.toString().trim());
	
        String userString = askString("Asking for a string", "Please type a string: ", "my default String");
        println("Entered String: " + userString);
    }
}
```

___Script1.properties___
```ini 
    # A comment line is indicated if the '#' or '!' character is the first non-whitespace character 
    # of that line.
    # 
    # Use a space-separated concatenation of the parameters to communicate which variable gets what 
    # value:
    #    Format:    <space-separated concatenation of parameters> = <value>
    #
    # Notice that spaces at the beginning and end of parameters are removed prior to concatenation.
    #
    # Note that if the askXxx() method contains a "defaultValue" parameter, that parameter should 
    # not be included in the concatenation of parameters.

    Choose a file Please choose a file: = /Users/username/help.exe
    Double dialog Please enter a double: = 32.2
    Address Enter an address! = 0x10AB34D
    Double dialog Please enter another double: = 3.14159 
    Asking for bytes Put some bytes here -- = AA BB CC 11 02 24
    Asking for a string Please type a string: = STRING ABC
```
 
__Note:__ If [script-specific arguments](#passing-parameters-using-arguments) have been passed into 
the script, the `askXxx()` methods will consume values found in the argument array rather than a 
_.properties_ file. The first `askXxx()` method will use the first value in the array, the second 
`askXxx()` method will use the second value in the array, and so on. If all of the arguments in the 
array have been consumed, the next `askXxx()` will throw an `IndexOutOfBoundsException`.

### Headless Scripts
A script of type _HeadlessScript_ (which extends _GhidraScript_) can be used by any user looking for
more control over the Headless Analysis process than is offered using the more generic 
_GhidraScript_ class. Using _HeadlessScripts_, users are able to store variables for use by later 
scripts, change the location of where an import will be saved, and change the disposition of a 
program depending on script-specific conditions (i.e., save it in a different folder, delete it, 
turn off analysis, abort further processing, etc.).

_HeadlessScripts_ allow the user to access certain methods that are specific to the 
HeadlessAnalyzer. Otherwise, these types of scripts operate exactly like _GhidraScripts_. Users 
should ___only___ use _HeadlessScript_ for headless operation. While _HeadlessScripts_ could 
possibly run successfully in the Ghidra GUI, an exception will be thrown if a HeadlessScript-only 
method is called during GUI operation.

#### Enabling/Disabling Analysis
In order to enable or disable analysis using a _HeadlessScript_, simply include the following line 
in your script:
```java
enableHeadlessAnalysis(true);  // turn on analysis
```
OR
```java
enableHeadlessAnalysis(false);  // turn off analysis
```

Note that a script that includes this line should be run as a `preScript`, since preScripts execute 
before analysis would typically run. Running the script as a `postScript` is ineffective, since the
stage at which analysis would have happened has already passed.

This change will persist throughout the current HeadlessAnalyzer session, unless changed again (in 
other words, once analysis is enabled via script for one program, it will also be enabled for future 
programs in the current session, unless changed).

Note: To check whether analysis is currently enabled, use the following method:
```java
boolean analysisEnabled = isHeadlessAnalysisEnabled();
```
    
#### Setting the Import Directory
When using [`-import`][import] mode, a user can change the path in the Ghidra project where imported
files are saved. This is done by using the following script method:
```java
setHeadlessImportDirectory("path/to/new/dir");
```

The new path does not have to exist (it will be created if it doesn't already exist). The path is 
also assumed to be relative to the project's root folder.

Here are some examples assuming the Ghidra project structure looks like this:
```
    MyGhidraProject:
        /dir1
            /innerDir1
            /innerDir2
```
* The following usage ensures that any files imported after the call to this method are saved in the
  existing `MyGhidraProject:dir1/innerDir2` folder:
  ```java
  setHeadlessImportDirectory("dir1/innerDir2");
  ```
* In contrast, the following usage adds new folders to the Ghidra project and saves the imported 
  files into the newly-created path.
  ```java
   setHeadlessImportDirectory("dir1/innerDir2/my/folder");
  ```
  changes the directory structure to:
  ```
    MyGhidraProject:
        /dir1
            /innerDir1
            /innerDir2
                /my
                    /folder
  ```
* Another usage example where new folders are added to the Ghidra project.
  ```java  
  setHeadlessImportDirectory("dir1/newDir/saveHere");
  ```
  This changes the directory structure to:
  ```
    MyGhidraProject:
        /dir1
            /innerDir1
            /innerDir2
            /newDir
                /saveHere
  ```

When using this method to set the save directory for imports, whether the save succeeds may depend 
on the state of the [`-overwrite`][overwrite] parameter. For example, if the new import location 
already exists and contains a file of the same name as the current program, the current program will
only be successfully saved if [`-overwrite`][overwrite] is enabled.

This change in import directory will persist throughout the current HeadlessAnalyzer session, unless 
changed again (in other words, once the import location has been changed, it will continue to be the 
import save location for future imported programs in the current session, unless changed again).

To revert back to the default import location (that which was specified via command line), pass the 
null object as the argument to this method:
```java
setHeadlessImportDirectory(null);    // Sets import save directory to default
```
The `setHeadlessImportDirectory()` method is ineffective in [`-process`][process] mode (the program 
will ___not___ be saved to a different location if this method is called when running in
[`-process`][process] mode).

#### Checking for Analysis Timeout
In the case where all of the following apply:
* the user set an analysis timeout period using the [`-analysisTimeoutPerFile`][timeout] parameter
* analysis is enabled and has completed
* the current script is being run as a postScript

The user can check whether analysis timed out, using the following query method:
```java
boolean didTimeout = analysisTimeoutOccurred();
```

#### Passing Values Between Scripts
If you are running multiple scripts in headless operation and would like to store a value in one 
script that is accessible by another script, use the _HeadlessScript_ methods below. They facilitate
the storage and retrieval of key-value pairs to/from a data structure that is available to any 
script of type _HeadlessScript_: 

```java
storeHeadlessValue(String key, Object value);
Object myObject = getStoredHeadlessValue(String key);
boolean containsKey = headlessStorageContainsKey(String key);
```

#### Using Scripts to Control Program Disposition
HeadlessScripts can be used to control disposition of the program currently being imported/processed 
(note: if running in [`-process`][process] mode with [`-readOnly`][readonly] enabled, programs can 
not be deleted, even if directed by a script).

The available options to control program disposition are as follows:		  
* `HeadlessContinuationOption.ABORT`
  * in [`-import`][import] mode, does not run any follow-on scripts/analysis; program is imported.
  * in [`-process`][process] mode, does not run any follow-on scripts/analysis; changes to the 
    current (existing) program are saved.
* `HeadlessContinuationOption.ABORT_AND_DELETE`
  * in [`-import`][import] mode, does not run any follow-on  scripts/analysis; program is not 
    imported.
  * in [`-process`][process] mode, does not run any follow-on scripts/analysis; the current 
    (existing) program is deleted.
* `HeadlessContinuationOption.CONTINUE_THEN_DELETE`
  * in [`-import`][import] mode, continues to run any follow-on scripts/analysis; program is not
    imported.
  * in [`-process`][process] mode, continues to run any follow-on scripts/analysis; the current 
    (existing) program is deleted after processing is complete.
* `HeadlessContinuationOption.CONTINUE` (__default setting__)
  * in [`-import`][import] mode, continues to run any follow-on scripts/analysis; program is 
    imported.
  * in [`-process`][process] mode, continues to run any follow-on scripts/analysis; changes to the 
    current (existing) program are saved.

To set the program disposition, use the `setHeadlessContinuationOption()` method. For example, to 
dictate that further processing be aborted and the program deleted, the script should use the 
following method with the `ABORT_AND_DELETE` option:

```java
setHeadlessContinuationOption(HeadlessContinuationOption.ABORT_AND_DELETE);
```

At the start of processing for each program (immediately before the first script runs), the 
script's continuation option is set to `CONTINUE` by default. If the 
`setHeadlessContinationOption()` method is not used, then operation continues as normal.

Note that when an option is set, it takes effect AFTER the current script completes. For example, 
setting the continuation option to `ABORT` does __not__ immediately abort the current script; 
instead, it aborts any processing (analysis, other scripts) that immediately follow the current 
script.

In the case where a subscript or secondary script sets an `ABORT`or `ABORT_AND_DELETE` option, that 
option will go into effect once the primary (or outermost) script has completed execution.

For a very basic example script, see _SetHeadlessContinuationOptionScript.java_, which is included 
in the Ghidra distribution.

When multiple scripts set program disposition, they are combined. Continue on to the next section
to understand how this works.

#### Using Multiple Scripts to Control Program Disposition
While running scripts that change the program disposition, there may be instances when the program 
disposition is changed more than once for the same program. Some cases where this could happen are:
* when the user runs multiple pre-scripts and/or post-scripts that use 
  `setHeadlessContinuationOption()`
* when the user runs scripts that call sub-scripts (or secondary scripts) that use 
  `setHeadlessContinuationOption()`
* when the user runs a script that makes multiple calls to the `setHeadlessContinuationOption()`
  method

If there are multiple calls to `setHeadlessContinuationOption()` within a single script, the last 
method call is used as the setting dictated by that script.

However, if multiple scripts make calls to `setHeadlessContinuationOption()`, the options from each
script are combined in a rational way (in the order the options were set) to potentially result in a
new continuation option. 

For example, if _Script1.java_ sets the continuation option (left column), then is followed by 
_Script2.java_ which also sets the continuation option (column headers), the resulting continuation 
status is shown in the following table:

|                          | ABORT             | ABORT_AND_DELETE  | CONTINUE_THEN_DELETE | CONTINUE             |
| ------------------------ | ----------------- | ----------------- | -------------------- | -------------------- |
| __ABORT__                | ABORT*            | ABORT*            | ABORT*               | ABORT*               |
| __ABORT_AND_DELETE__     | ABORT_AND_DELETE* | ABORT_AND_DELETE* | ABORT_AND_DELETE*    | ABORT_AND_DELETE*    |
| __CONTINUE_THEN_DELETE__ | ABORT_AND_DELETE  | ABORT_AND_DELETE  | CONTINUE_THEN_DELETE | CONTINUE_THEN_DELETE |
| __CONTINUE__             | ABORT             | ABORT_AND_DELETE  | CONTINUE_THEN_DELETE | CONTINUE             |

__*NOTE:__ In cases where _Script1_ specifies `ABORT` or `ABORT_AND_DELETE`, _Script2_ will not run 
unless _Script2_ is a subscript or secondary script called by _Script1_.

Keep in mind:
* If _Script2_ does not change the continuation option, then the status from _Script1_ will carry 
  over.
* An `ABORT` at the postScript stage is still meaningful in stopping further processing, since 
  follow-on analysis may occur as a result of changes made by the postScript.
* You can check the current continuation option by using the `getHeadlessContinuationOption()` 
  method. For example:
  ```java
  HeadlessContinuationOption currentOption = getHeadlessContinuationOption();
  ```
  * When specifying deletion options such as `ABORT_AND_DELETE` or `CONTINUE_THEN_DELETE` in 
     [`-process`][process] mode, be sure to include [`-okToDelete`][oktodelete] in the command line 
     parameters to verify that deletions are allowed. This is an extra safety step to ensure 
     programs aren't deleted when the user didn't mean to delete them.

## Wildcards
Wildcards can be used when specifying files and/or directories for [`-import`][import] mode, or when
specifying one or more files for [`-process`][process] mode. Wildcards in [`-import`][import] mode 
are expanded by the underlying system shell before being passed on to headless Ghidra (consequently,
any wildcard limitations will be dictated by the specific operating system you are using). Wildcards
in [`-process`][process] mode are expanded by headless Ghidra and are limited to the use of `*` and
`?` only.

Note that wildcarding is NOT supported for specifying the Ghidra project/repository location or 
folder path. 

Below are some general guidelines for wildcard usage:
* [`-import`][import] mode
  * During import, the rules for wildcard use depend on the operating system on which the Headless
    Analyzer is being run. The operating system will expand the wildcards to a list of matching
    files and pass the list to the Headless Analyzer.
  * Unix-based Operating Systems allow the following wildcards:
    * Use the `*` character to substitute for zero or more characters
    * Use the `?` character to substitute for exactly one character
    * Use ranges of characters enclosed in square brackets (for example, `[a-z]`) to substitute for
      any one of the characters in that range. Negation of the characters is also allowed by using a
      leading `!` within the brackets (i.e., `[!a-z]`).
    * Wildcards can expand to either directories or files
  * Windows allows the following wildcards:
    * Use the `*` character to substitute for zero or more characters
    * Use the `?` to substitute for one character or less
    * Wildcards can only expand to files (directories whose names conform to the wildcard string 
      will not be returned)
  * When using a wildcard to specify files, be sure to use as specific of a string as possible. 
    There may be unintended consequences to using more generalized wildcard strings, such as:
    ```bash
    ./analyzeHeadless /home/usr/ghidra/projects TestProj -import /home/files/n*
    ```
    When using a Unix-based operating system, this import specification results in not only all 
    files in `/home/files` starting with _n_ to be imported, but also the contents of the all 
    directories starting with _n_ to be imported (contents of those directories' subdirectories 
    would also be imported, if the [`-recursive`][recursive] option was specified -- note  that the
    contents of the directories starting with _n_ are not also subject to the restriction that they
    start with _n_).

* [`-process`][process] mode
  * In process mode, the wildcard string applies only to files, not directories. The only accepted
    wildcard characters are `*` and `?`.
  * There are some cases where the wildcard string may be prematurely expanded by the operating 
    system. For example, in order to run in [`-process`][process] mode over all existing project 
    files that start with the letter _a_, one might use the following command:
    ```bash
    ./analyzeHeadless /home/usr/ghidra/projects TestProj -process a* -recursive
    ```
  * Instead of the "a*" string being passed along to be used within the Ghidra project, the shell 
    will prematurely expand the wildcard string to match all _a_-prefixed files in the current 
    directory. The command ends up looking like this:
    ```bash
    ./analyzeHeadless /home/usr/ghidra/projects TestProj -process analyzeHeadless -recursive
    ```
  * In order to prevent the system shell from doing this premature wildcard expansion, simply 
    surround the wildcard string with single-quote characters:
    ```bash
    ./analyzeHeadless /home/usr/ghidra/projects TestProj -process 'a*' -recursive
    ```

[projectlocation]: #project_location
[projectname]: #project_namefolder_path
[ghidraserver]: #ghidraserverportrepository_namefolder_path
[import]: #-import-directoryfile
[process]: #-process-project_file
[prescript]: #-prescript-scriptnameext-arg
[postscript]: #-postscript-scriptnameext-arg
[scriptpath]: #-scriptpath-path1path2
[propertiespath]: #-propertiespath-path1path2
[scriptlog]: #-scriptlog-path-to-script-log-file
[log]: #-log-path-to-log-file
[overwrite]: #-overwrite
[recursive]: #-recursive-depth
[readonly]: #-readonly
[deleteproject]: #-deleteproject
[noanalysis]: #-noanalysis
[processor]: #-processor-languageid
[cspec]: #-cspec-compilerspecid
[timeout]: #-analysistimeoutperfile-timeout-in-seconds
[keystore]: #-keystore-keystorepath
[connect]: #-connect-userid
[password]: #-p
[commit]: #-commit-comment
[oktodelete]: #-oktodelete
[maxcpu]: #-max-cpu-max-cpu-cores-to-use
[libarysearchpaths]: #-librarysearchpaths-path1path2
[loader]: #-loader-desired-loader-name

[headlessdispo]: #using-scripts-to-control-program-disposition
[headlessdispomulti]: #using-multiple-scripts-to-control-program-disposition

[^1]: Address must be in the form `[space:]offset`. Space is optional, and offset is a hex valuewith no leading `0x`.
[^2]: To specify hexadecimal, use a leading `0x`.
[^3]: Base address is in the default space and must be specified as a hexadecimal value without the leading `0x`.
[^4]: Base address is in the default data space and must be specified as a hexadecimal value without the leading `0x`.
      This option only applies to Harvard Architecture processors when loading relocatable ELF binaries (i.e., object modules).