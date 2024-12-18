//@title java
////@image-opt env:OPT_TARGET_CLASS
//@timeout 2000000
//@desc <html><body width="300px">
//@desc   <h3>Launch with <tt>java</tt></h3>
//@desc   <p>
//@desc     This will launch the target on the local machine using <tt>java</tt>.
//@desc     For setup instructions, press <b>F1</b>.
//@desc   </p>
//@desc </body></html>
//@menu-group local
//@icon icon.debugger
//@help TraceRmiLauncherServicePlugin#java
//@env OPT_TARGET_CLASS:str="" "Image" "The Main Class to launch (defaults to current program)."
//@env OPT_TARGET_CLASSPATH:str="" "ClassPath" "The JVM classpath"
//@args "Arguments" "Command-line arguments to pass to the target"
//@enum Arch:str JVM Dalvik
//@env OPT_ARCH:Arch="JVM" "Arch" "Either 'JVM' or 'Dalvik'"
////@env OPT_SUSPEND:bool=true "Suspend" "Suspend the VM on launch."
//@env OPT_INCLUDE:str=n "Include virtual threads" "Include virtual threads."
//@env OPT_JSHELL_PATH:file="" "JShell cmd (if desired)" "The full path to jshell."

import ghidra.dbg.jdi.rmi.jpda.*;

// NB. The jshell code here is user modifiable; however, the user must provide OPT_JSHEL_PATH when
// prompted in Ghidra' UI, or else this script is completely bypassed. Without a jshell, Ghidra
// calls new JdiClientThread(env).start() directly.

GhidraJdiInit.initApp()
JdiClientThread thread = new JdiClientThread(System.getenv());
thread.start();
