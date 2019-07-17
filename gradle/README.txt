This folder contains the gradle scripts for the build system.  The gradle files at this level are
intended to be included by individual gradle project's build.gradle files. They add support for 
specific capabilities and are described below.  There are also two sub-folders.  The sub-folder 
"root" contains gradle scripts that are applied only to the root project's build.gradle file and 
are just a way to organize and break up the root project's build code.  The other sub-folder "support"
contains gradle scripts applied from other gradle scripts, mainly to avoid duplication of code. 

The following gradle scripts can be applied to a project's build.gradle file to add support for various capabilities.

javaProject.gradle - apply if the project contains java code.
nativeProject.gradle - apply if the project contains native code.
processorProject.gradle - apply if the project contains processor language specification.
helpProject.gradle - apply if the project contains files for the Ghidra help system.
javaTestProject.gradle - apply if the project contains unit tests.
jacocoProject.gradle - apply to the project to include it in when running the Jacoco task.

The following scripts can be included if the project is to be included in the build process. Only 
one of these scripts should be applied to a project.

distributableGhidraModule.gradle - apply if the Ghidra module should be included in the distribution build.
distributableGhidraExtension.gradle - apply if the Ghidra extension should be included in the distribution build.
externalGhidraExtension.gradle - apply if the Ghidra extension should be built external to the distribution build.
