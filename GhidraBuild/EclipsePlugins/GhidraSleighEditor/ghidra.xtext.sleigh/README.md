# GhidraSleighEditor Eclipse Plugin

GhidraSleighEditor makes developing and modifying Ghidra Sleigh processor modules much more 
enjoyable by providing a modern day context sensitive editor with syntax highlighting, navigation, 
context sensitive error notation, quick fixes, and more.  The editor is built with the excellent 
XTEXT DSL framework within Eclipse.

The information provided in this document is effective as of Ghidra Sleigh Editor 1.0.0 and is 
subject to change with future releases.

## Table of Contents
1. [Change History](#change-history)
2. [Minimum Requirements](#minimum-requirements)
3. [Installing](#installing)
4. [GhidraSleighEditor Features](#ghidrasleigheditor-features)
   * [Syntax Highlighting](#syntax-highlighting)
   * [Validation](#validation)
   * [QuickFix](#quickfix)
   * [Hover](#hover)
   * [Find References](#find-references)
   * [Renaming](#renaming)
   * [Code Formating](#code-formatting)
5. [Uninstalling](#uninstalling)
6. [Upgrading](#upgrading)
7. [Building](#building)

## Change History
__1.0.2:__
* Added `lzcount` to grammar
* Fixed cpool invalid error, and added test for cpool arguments

__1.0.1:__
* Added support for new endian tag on `define token` definitions
* Bug fix for `@if "!="` comparison
* Added `popcount` to grammar

__1.0.0:__
* Initial release

## Minimum Requirements
* Eclipse 2019-3 with DSL and XTEXT 2.17 or later

## Installing
GhidraSleighEditor is installed manually into Eclipse and should be installed by anyone interested 
in working with processor module sleigh specifications. The GhidraSleighEditor must be manually 
installed in Eclipse. In the future the extension may be installed automatically along with the 
GhidraDev Eclipse plugin when setting up Eclipse for Ghidra scripting and plugin development.

GhidraSleighEditor can be installed into an existing installation of Eclipse the same way most 
Eclipse plugins are installed. From Eclipse:
 1. Click `Help -> Install New Software...`
 2. Click `Add...`
 3. Click `Archive...`
 4. Select GhidraSleighEditor zip file from 
    `<GhidraInstallDir>/Extensions/Eclipse/GhidraSleighEditor/`
 5. Click `OK` (name field can be blank)
 6. Check `Ghidra` category (or `Ghidra Sleigh Editor` entry)
 7. Click `Next`
 8. Click `Next`
 9. Accept the terms of the license agreement
10. Click `Finish`
11. Click `Install anyway`
12. Click `Restart Now`

## GhidraSleighEditor Features
The Ghidra Sleigh Editor provides a variety of features one would expect in any modern IDE to make
viewing, modifying, debugging, and creating Sleigh processor specifications as painless as possible.
Once installed, any `.sinc` or `.slaspec` file that is edited will be brought up in the sleigh 
editor.

The editor provides the following capabilities:

### Syntax Highlighting
Keywords, Tokens, Sub-constructor names, Comments, Instruction Formats, Strings, Variables, and more
can be colorized to make the sliegh specification more readable. In the 
`Window -> Preferences -> Sleigh` preferences panel, the color and font style can be changed for any
sleigh file tokens.

### Validation
The structure of a sleigh file while fairly simple can lend itself to errors when using a straight
text editor. The editor understands the syntax and all constructs of a sleigh file. Instead of 
waiting for the sleigh compiler to produce an error, many but not all syntax errors can be caught 
and displayed with a red error marker.

The editor validates the definition of variables including locals. Though legal in the sleigh 
compiler, it has been found that not declaring local variables leads to errors that are not be
caught by the sleigh compiler. For example, assigning to a variable `ro` when the actual register 
name is `r0` may go unnoticed. All local variables must be defined with with the `local` keyword or
with an initial `:size`.

Warnings on duplicate names of tokens is marked in yellow. Complex matching patterns such as 
`'!='  '<'  '>'` are warnings as well. Using comparison matching operators can cause the generated 
.sla file to be much larger than necessary. Comparison matching should really never be used on any
tokens that are bigger than a few bits as the number of match cases generated will be large. Their 
use is unavoidable in some cases.

There are some artificial enforcements in the editor that, while valid sleigh syntax, cause the 
syntax to be unparsable. Because the sleigh Domain Specific Language (DSL) is a context sensitive 
grammer, as well as using define-like pre-processing expansion, the editor only allows define
`$()` variables at certain locations where a single token would reside. The most common flagged 
error is embedding a connecting `&` in a define and then using it an a match pattern:
`:MOV ax, bx is t1=1 $(BadDefine) {}` is not allowed, and instead should be 
`:MOV ax, bx is t1=1 & $(GoodDefine) {}`.

### QuickFix
Some simple syntax errors can be fixed quickly with QuickFix suggestions. Pressing `Crtl-1` on an 
error will bring up available quick-fixes:
* _Undefined local variable_ - insert `local` or the `:size` form if the size can be detected.
* _Undefined user pcodeop_ - can insert a user pcodeop definition for an unknown identifier
* _Undefined macro_ - can insert a macro definition for an unknown identifier
* _Add token field definition_ - for an unknown token in the match pattern

More quick-fixes may be added in the future. Please note quickfixes can be slow on large files such
as the AARCH64.
  
### Hover
There are many constructs in a sleigh file that, when hovered over, will display additional
information. This is especially useful for tokens to get their size without having to navigate to
the token field definition. More hovers will be added.
* Sub-Constructors will display all the defined sub-constructors with the same name.
* Token field definitions will display their size, and if attached, the set of registers.
* Registers display their size.
* Numeric values will display in Hex, Binary, and Decimal.
* `$(Defines)` display all the possible defines for the name, since the actual define used can't be
  known.
  	
### Navigation
If you have edited a sleigh processor specification in a regular text editor, you will appreciate 
the forward and backward navigation supported on various variable name use and their associated 
definition. Navigation is supported on sub-constructor names, field token names, registers, macros
names, local variables, define names, and user define pcodeop's.

Navigate by pressing `F3` on a variable, using the forward/backward navigation arrows, or my 
favorite the `<-*` that will navigate back to the last edit location.
   
### Find References
Instead of keyword searching, the editor provides a find all uses of a variable. Each found use is
listed in a search window with the text of the line where it is used displayed. Each found location
can also be navigated to by double clicking on the found reference.

Use the editor popup menu `Find References` action.
   
### Renaming
The name of variables can be very important, and instead of doing a search and replace on a string, 
the editor can refactor a name and change all other uses of that name. The name is even changed in 
other `.sinc` and `.slaspec` files.

Use the editor popup menu `Rename Element` action.
   
### Code Formatting
Sleigh files can get large and messy during development. Instead of paying much attention to format,
or trying to format by hand you can use the Source Format action. Common constructs are lined up, 
for example the token definitions will find the longest token and line up all other tokens and their
definition. All sub-constructors of the same name will be lined up on the `is` keyword, the match 
pattern, and the semantic definitions. All constructors `is` keywords will be generally lined up 
based on the longest print peice for each constructor. Statements will also be indented 
consistently. Multi-line attach definitions will have each entry lined up. Formatting can be 
restricted to a selection of lines to stop formatting from entirely re-formatting carefully 
formatted files. Additional formatting may be added in the future, and the formatter may become more
configurable in the future.

Use the editor popup menu `Source -> Format` action.`

## Uninstalling
GhidraSleighEditor can be uninstalled as follows from Eclipse:
1. Click `Help -> About Eclipse`
   * For macOS, `Eclipse -> About Eclipse`
2. Click `Installation Details`
3. Select Ghidra Sleigh Editor
4. Click `Uninstall...`
5. Select Ghidra Sleigh Editor
6. Click `Finish`
7. Click `Restart Now`

## Upgrading
GhidraSleighEditor can be upgraded the same way it was initially installed.

## Building
The GhidraSleighEditor is currently built from Eclipse and distributed with Ghidra manually.
Ideally we will use Gradle one day, but we aren't there yet. We do rely on `gradle prepDev` to 
generate the Eclipse project and  build GhidraSleighEditor's dependencies though, hence the 
build.gradle file.

__NOTE:__ Only "Eclipse IDE for Java and DSL Developers" has the ability to do the below 
instructions. The following instructions assume that you are using this version of Eclipse.

It is also suggested that you use the "Eclipse IDE for Java and DSL Developers" if you will
use the GhidraSleighEditor. You can build the GhidraSleighEditor installation zip with the XTEXT 
runtime in the plugin. The XTEXT runtime was not included in the distribution build because it would
have added 80Meg.

Importing GhidraSleighEditor Eclipse projects (they are deactivated by default):
1. Uncomment the line in `settings.gradle` that includes the GhidraSleighEditor project.
2. Run `gradle eclipse -PeclipseDSL` to generate the GhidraSleighEditor Eclipse projects.
3. From Eclipse, `File -> Import -> General -> Existing Projects into Workspace`.
4. From the ghidra repo, import all "Eclipse GhidraSleighEditor *" projects.
  
Generating all Sleigh XTEXT generated files:
1. Open "Eclipse SleighEditor" project.
2. Navigate to the file `src -> ghidra.xtext.sleigh -> GenerateSleigh.mwe2`
3. __NOTE:__ The following will download a jar file from the internet (not from NSA) unless you 
   pre-download.
   1. Download the file http://download.itemis.com/antlr-generator-3.2.0-patch.jar
   2. Put the file in `ghidra/GhidraBuild/EclipsePlugins/SleighEditor/ghidra.xtext.sleigh`
   3. Rename the file to `.antlr-generator-3.2.0-patch.jar`
4. From the popup menu `RunAs -> MWE2 Workflow`
   * Files in xtend-gen and src-gen will be created
5. If there are any red bookmarks on any of the Eclipse Sleigh* projects,
   * Select all the Eclipse Sleigh* projects, and refresh from the popup menu
   * The project should rebuild, and there should be no red Problem errors

Try out the Sleigh Editor
1. Navigate to the `Eclipse SleighEditor` and chose `RunAs -> Eclipse Runtime`
2. Add a sleigh processor module
   1. `File -> NewJavaProject...`
      * Uncheck default location and navigate to a processor in `Ghidra/Processors/<X>`
      * The project be automatically named `<X>`
      * Finish
      * Cancel Module creation
      * Navigate to a `<X>/data/languages/<file>.sinc` or `<file>.slaspec`
      * On the popup asking to convert to an XTEXT project, choose "Yes"
   2. -OR-
      * Drop a `.slaspec` or `.sinc` file from the file browser on eclipse
      * This is good for quick viewing, however navigation across files may not work.
  
Optional: Changing version number (GhidraSleighEditor is versioned independently of Ghidra):
1. Open `feature.xml` in the GhidraSleighEditor Feature project.
2. In the "Overview" tab, update the "Version" field to `x.y.z.qualifier` and save.
3. Open `category.xml` in the GhidraSleighEditor Feature project.
4. Highlight `ghidra.xtext.sleigh.editor (x.y.z.qualifier)`, and click "Remove".
5. Highlight `ghidra.xtext.sleigh.editor`, and click "Add Feature".
6. Select `ghidra.ghidradev (x.y.z.qualifer)`, click "OK", and save.
7. Update "Change History" section of this document if necessary.

Optional: Including the XTEXT runtime
You can include the XTEXT runtime or redist module in the .zip file which will negate the need to 
have Eclipse with the DSL in the Eclipse into which the Eclipse Sleigh Editor is installed to run.
1. Navigate to the ghidra.xtext.sleigh.feature
2. bring up the feature.xml with the Feature Manager Editor (dbl-click on it).
3. Go to the Included Features tab
4. Add...
5. Filter by `redist` and add `org.eclipse.xtext.redist`

Creating an installation zip file to install in Eclipse:
1. Do a `gradle prepDev` to ensure GhidraSleighEditor's dependencies are up-to-date.
2. `File -> Export -> Plug-in Development -> Deployable plugins and fragments`
3. Select `Archive file` and choose a directory to save it to. Name it 
   `GhidraSleighEditor-x.y.z.zip`.
4. In the "Options" tab make sure things look like this:
   * Export source: UNCHECKED
   * Package as individual JAR archives: CHECKED
   * Generate p2 repository: CHECKED
   * Categorize repository: CHECKED
   * Qualifier replacement: CHECKED + clear field so default is used
   * Save as Ant script: UNCHECKED
   * Allow for binary cycles in target platform: CHECKED
   * Use class files compiled in the workspace: UNCHECKED
5. Finish
