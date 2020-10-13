The Ghidra Sleigh Editor for Eclipse is currently built from Eclipse and checked into the bin repo.
Ideally we will use Gradle one day, but we aren't there yet.  We do rely on Gradle prepDev to generate
the Eclipse project and  build GhidraSleighEditor's dependencies though, hence the build.gradle file.

Required: Eclipse IDE with Java and DSL version 2019-03 or later, XTEXT 2.17 or later.
          The following instructions assume that you have setup Eclipse.

It is also suggested that you use the Eclipse IDE with DSL extensions already installed if you will
use the GhidraSleighEditor. You can build the GhidraSleighEditor installation zip with the XTEXT runtime
in the plugin.  The XTEXT runtime was not included in the distribution build because it would
have added 80Meg.


Importing GhidraSleighEditor Eclipse projects (they are deactivated by default):
  1) Uncomment the line in settings.gradle that includes the GhidraSleighEditor project.
  2) Run "gradle eclipse -PeclipseDSL" to generate the GhidraSleighEditor Eclipse projects.
  3) From Eclipse, File --> Import --> General --> Existing Projects into Workspace
  4) From the ghidra repo, import all "Eclipse GhidraSleighEditor *" projects.
 
  
Generating all Sleigh XTEXT generated files:
  1) open "Eclipse SleighEditor" project
  2) navigate to the file src --> ghidra.xtext.sleigh --> GenerateSleigh.mwe2
  3) NOTE: the following will download a jar file from the internet (not from NSA)
     unless you pre-download.
     3a) Download the file http://download.itemis.com/antlr-generator-3.2.0-patch.jar
     3b) Put the file in ghidra/GhidraBuild/EclipsePlugins/SleighEditor/ghidra.xtext.sleigh
     3c) Rename the file to .antlr-generator-3.2.0-patch.jar
  3) From the popup menu RunAs --> MWE2 Workflow
     - Files in xtend-gen and src-gen will be created
  4) If there are any red bookmarks on any of the Eclipse Sliehg* projects,
     - Select all the Eclipse Sleigh* projects, and refresh from the popup menu
     - The project should rebuild, and there should be no red Problem errors


Try out the Sleigh Editor
  1) Navigate to the 'Eclipse SleighEditor' and chose RunAs --> Eclipse Runtime
  2) Add a sleigh processor module
  2a) File --> NewJavaProject...
       - Uncheck default location and navigate to a processor in Ghidra/Processors/<X>
       - The project be automatically named <X>
       - Finish
       - Cancel Module creation
       - Navigate to a <X>/data/languages/<file>.sinc or <file>.slaspec
       - On the popup asking to convert to an XTEXT project, choose "Yes"
  2b) -OR-
       - drop a .slaspec or .sinc file from the file browser on eclipse
       - this is good for quick viewing, however navigation across files may not work.
  

Optional: Changing version number (GhidraSleighEditor is versioned independently of Ghidra):
  1) Open feature.xml in the GhidraSleighEditor Feature project.
  2) In the "Overview" tab, update the "Version" field to x.y.z.qualifier and save.
  3) Open category.xml in the GhidraSleighEditor Feature project.
  4) Highlight ghidra.xtext.sleigh.editor (x.y.z.qualifier), and click "Remove".
  5) Highlight ghidra.xtext.sleigh.editor, and click "Add Feature".
  6) Select ghidra.ghidradev (x.y.z.qualifer), click "OK", and save.
  7) Update GhidraDev_README.html "Change History" section if necessary.


Optional: Including the XTEXT runtime
You can include the XTEXT runtime or redist module in the .zip file which will negate the need
to have Eclipse with the DSL in the Eclipse into which the Eclipse Sleigh Editor is installed to run.
  1) Navigate to the ghidra.xtext.sleigh.feature
  2) bring up the feature.xml with the Feature Manager Editor (dbl-click on it).
  3) Go to the Included Features tab
  4) Add...
  5) Filter by 'redist' and add org.eclipse.xtext.redist
      

Creating an installation zip file to install in Eclipse:
  1) Do a Gradle prepDev to ensure GhidraDev's dependencies are up-to-date.
  2) File --> Export --> Plug-in Development --> Deployable plugins and fragments
  4) Select "Archive file" and choose a directory to save it to.  It must end up in
     ghidra.bin/GhidraBuild/Eclipse/GhidraDev/.  Name it GhidraDev-x.y.z.zip.
  5) In the "Options" tab make sure things look like this:
     - Export source: UNCHECKED
     - Package as individual JAR archives: CHECKED
     - Generate p2 repository: CHECKED
     - Categorize repository: CHECKED.
     - Qualifier replacement: CHECKED + clear field so default is used
     - Save as Ant script: UNCHECKED
     - Allow for binary cycles in target platform: CHECKED
     - Use class files compiled in the workspace: UNCHECKED
  6) Finish
