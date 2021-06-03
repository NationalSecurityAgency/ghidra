GhidraDev is currently built from Eclipse and checked into the bin repo.  Ideally we will use Gradle
one day, but we aren't there yet.  We do rely on Gradle prepDev to generate the Eclipse project and 
build GhidraDev's dependencies though, hence the build.gradle file.

NOTE: Only "Eclipse for RCP and RAP Developers" has the ability to do the below instructions.  The
following instructions assume that you are using this version of Eclipse.

Importing GhidraDev Eclipse projects (they are deactivated by default):
  1) Run gradle eclipse -PeclipsePDE
  2) From Eclipse, File --> Import --> General --> Existing Projects into Workspace
  3) From the ghidra repo, import "Eclipse GhidraDevFeature" and "Eclipse GhidraDevPlugin".

Changing version number (GhidraDev is versioned independently of Ghidra):
  1) Open plugin.xml in the GhidraDevPlugin project.
  2) In the "Overview" tab, update the "Version" field to x.y.z.qualifier and save.
  3) Open feature.xml in the GhidraDevFeature project.
  4) In the "Overview" tab, update the "Version" field to x.y.z.qualifier and save.
  5) Open category.xml in the GhidraDevFeature project.
  6) Highlight ghidra.ghidradev (x.y.z.qualifier), and click "Remove".
  7) Highlight ghidra.ghidradev, and click "Add Feature".
  8) Select ghidra.ghidradev (x.y.z.qualifer), click "OK", and save.
  9) Update GhidraDev_README.html "Change History" section if necessary.

Building from Eclipse:
  1) Do a Gradle prepDev to ensure GhidraDev's dependencies are up-to-date.
  2) File --> Export --> Plug-in Development --> Deployable features
  3) Check ghidra.ghidradev (x.y.z.qualifier)
  4) Select "Archive file" and choose a directory to save it to.  It must end up in
     ghidra.bin/GhidraBuild/EclipsePlugins/GhidraDev/.  Name it GhidraDev-x.y.z.zip.
  5) In the "Options" tab make sure things look like this:
     - Export source: UNCHECKED
     - Package as individual JAR archives: CHECKED
     - Generate p2 repository: CHECKED
     - Categorize repository: CHECKED + Browse to category.xml file in the GhidraDevFeature project.
     - Qualifier replacement: CHECKED + clear field so default is used
     - Save as Ant script: UNCHECKED
     - Allow for binary cycles in target platform: CHECKED
     - Use class files compiled in the workspace: UNCHECKED
  6) Finish
