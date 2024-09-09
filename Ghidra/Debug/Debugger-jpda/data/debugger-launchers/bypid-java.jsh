//@title java attach PID
//@timeout 20000
//@desc <html><body width="300px">
//@desc   <h3>Attach with <tt>java</tt></h3>
//@desc   <p>
//@desc     This will attach to the target with a specified PID.
//@desc     For setup instructions, press <b>F1</b>.
//@desc   </p>
//@desc </body></html>
//@menu-group attach
//@icon icon.debugger
//@help TraceRmiLauncherServicePlugin#java_bypid
//@enum Arch:str JVM Dalvik
//@env OPT_ARCH:Arch="JVM" "Arch" "Target architecture"
//@env OPT_PID:str="" "Pid" "The target process id"
//@env OPT_TIMEOUT:str="0" "Timeout" "Connection timeout"
//@env OPT_JSHELL_PATH:file="" "JShell cmd (if desired)" "The full path to jshell."

import ghidra.dbg.jdi.rmi.jpda.*;

// NB. The jshell code here is user modifiable; however, the user must provide OPT_JSHEL_PATH when
// prompted in Ghidra' UI, or else this script is completely bypassed. Without a jshell, Ghidra
// calls new JdiClientThread(env).start() directly.

GhidraJdiInit.initApp()
JdiClientThread thread = new JdiClientThread(System.getenv());
thread.start();
