//@title java attach port
//@timeout 20000
//@desc <html><body width="300px">
//@desc   <h3>Attach with <tt>java</tt></h3>
//@desc   <p>
//@desc     This will attach to the target at HOST:PORT.
//@desc     For setup instructions, press <b>F1</b>.
//@desc   </p>
//@desc </body></html>
//@menu-group attach
//@icon icon.debugger
//@help TraceRmiLauncherServicePlugin#java_attach
//@enum Arch:str JVM Dalvik
//@env OPT_ARCH:Arch="JVM" "Arch" "Target architecture"
//@env OPT_HOST:str="localhost" "Host" "The hostname of the target"
//@env OPT_PORT:str="54321" "Port" "The host's listening port"
//@env OPT_TIMEOUT:str="0" "Timeout" "Connection timeout"
//@env OPT_JSHELL_PATH:file="" "JShell cmd (if desired)" "The full path to jshell."

import ghidra.dbg.jdi.rmi.jpda.*;

// NB. The jshell code here is user modifiable; however, the user must provide OPT_JSHEL_PATH when
// prompted in Ghidra' UI, or else this script is completely bypassed. Without a jshell, Ghidra
// calls new JdiClientThread(env).start() directly.

GhidraJdiInit.initApp()
JdiClientThread thread = new JdiClientThread(System.getenv());
thread.start();
