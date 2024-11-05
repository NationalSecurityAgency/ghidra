# Debugger-agent-frida

## Random Notes on the Implementation of Debugger-agent-frida

Building libfrida-core.so:
* You can download libfrida-core.a for Frida by grabbing the latest frida-core-devkit for your OS 
  from https://github.com/frida/frida/releases or by downloading the Frida source and running:
  `python3 devkit.py frida-core linux-x86_64 DEVKIT` from the `releng` directory. 
	
Ghidra needs a dynamically-loadable version of libfrida-core.a which you can generate by something like:
```bash
cp ghidra_wrapper.c into the directory with libfrida-core.a and frida-core.h (distro or DEVKIT)
g++ -shared ghidra_wrapper.c ./libfrida-core.a -o libfrida-core.so
```

Libfrida-core.so should then be added to the `j`na.library.path`or put someplace like
`/usr/lib/x86_64-linux-gnu`, where it will get picked up by `Native.load()`.

### Frida Functionality
The most interesting bits of Frida are available as "methods" from the Objects Tree.  For instance, 
if you select a function and hit `M`, you will get a dialog with available methods.  Selecting, 
for example, `intercept` will bring up a second dialog with the relevant parameters.  For many of 
these, you will want to provide your own Javascript `on` functions, e.g. `onEnter` for the 
Interceptor. Stalking is available on Threads and the individual thread entries. Scan, protect, and 
watch functions are available on Memory. You can also redirect the output to GhidraScript, although
this relies on a bit of a hack.  If your Javascript `Name` parameter is something like 
`interpreter`, prepend `interpreter<=` to the output from your Javascript, and the results will be 
passed to both the console and the script.
	
### State in Frida
Commands in Frida are, generally speaking, not state-dependent, i.e. they do not depend on whether 
the target is running or not, only on whether the frida-agent thread is running. Many of the 
gum-based commands do, however, depend on ptrace.  If you have a ptrace-based debugger attached to 
the target, they will time out.  You can attach a debugger after Frida, but you will have to detach 
it to regain the gum-based functionality.  "Detach" in most debuggers includes "resume", so it is 
difficult to get state other than the "initial" state from the frida-agent injection point.  It 
would be nice if "disconnect" worked, but "disconnect" (i.e. detach without resuming) also leaves 
Frida in a partially disabled state.
	
### Errors in Frida
The cloaking logic in Frida, e.g. in `gum_cloak_add_thread` and `gum_cloak_index_of_thread`, is 
broken as of the writing of this note.  `gum_cloak_add_thread` is called for every thread, and 
`gum_cloak_index_of_thread` returns a non-negative result for every call but the first.  As a 
result, every thread but one is cloaked, and `enumerateThreads`returns only a single thread. This is
documented in `Issue #625` for the frida-gum project.  A quick fix is to comment out the cloaking 
call in `frida-gum/gum/gumprocess.c::gum_emit_thread_if_not_cloaked`.  Obviously, this may have 
other undesirable effects, but...
	
The logic in the ordering of exception handlers also appears to be broken (`Issue #627`). New 
handlers are appended to the queue, in most cases after `gum_exceptor_handle_scope_exception` and 
`gum_quick_core_handle_crashed_js`. `gum_exceptor_handle_scope_exception` almost always returns 
`TRUE`, breaking out of the queue and causing any remaining handlers to be ignored. This means any 
handler added with `Process.setExceptionHandler` is likely to be ignored.  A quick fix is to modify
`gum_exceptor_add` to use `g_slist_prepend instead` of `g_slist_append`.
	
Not really an error, but worth noting: building `libfrida-core.so` from the source may result in a 
library with glib2.0 dependencies that are incompatible with the current version of Eclipse. The 
not-so-simple solution is to build Eclipse on the machine that you used to build `libfrida-core`.
