/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.python;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.*;
import java.net.InetAddress;
import java.net.Socket;
import java.util.*;

import org.python.core.*;
import org.python.util.InteractiveInterpreter;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;

/**
 * A python interpreter meant for Ghidra's use.  Each interpreter you get will have its own
 * variable space so they should not interfere with each other.
 * <p>
 * There is no longer a way to reset an interpreter...it was too complicated to get right.
 * Instead, you should {@link #cleanup()} your old interpreter and make a new one.
 */
public class GhidraPythonInterpreter extends InteractiveInterpreter {

	private static boolean pythonInitialized;
	private static List<PyString> defaultPythonPath;

	private TraceFunction interruptTraceFunction;
	private PyModule introspectModule;
	private PyModule builtinModule;
	private PyObject interrupt;
	private boolean scriptMethodsInjected;
	private boolean cleanedUp;

	/**
	 * Gets a new GhidraPythonInterpreter instance.
	 *
	 * @return A new GhidraPythonInterpreter. Could be null if it failed to be created.
	 */
	public static GhidraPythonInterpreter get() {

		// Initialize the python environment if necessary.  Only needs to happen once.
		if (!pythonInitialized) {
			try {
				// Setup python home directory
				PythonUtils.setupPythonHomeDir();

				// Setup python cache directory
				PythonUtils.setupPythonCacheDir(TaskMonitor.DUMMY);

				// Indicate that we've initialized the python environment, which should
				// only happen once.
				pythonInitialized = true;
			}
			catch (Exception e) {
				Msg.showError(GhidraPythonInterpreter.class, null, "Python error",
					"Problem getting Ghirda Python interpreter", e);
				return null;
			}
		}

		// Set up our default system state, including prompt styles.
		PySystemState state = new PySystemState();
		state.ps1 = new PyString(">>> ");
		state.ps2 = new PyString("... ");

		// Return a new instance of our interpreter
		return new GhidraPythonInterpreter(state);
	}

	/**
	 * Creates a new Ghidra python interpreter object.
	 *
	 * @param state The initial system state of the interpreter.
	 */
	private GhidraPythonInterpreter(PySystemState state) {
		super(null, state);

		// Store the default python path in case we need to reset it later.
		defaultPythonPath = new ArrayList<>();
		for (Object object : systemState.path) {
			defaultPythonPath.add(Py.newStringOrUnicode(object.toString()));
		}

		// Allow interruption of python code to occur when various code paths are
		// encountered.
		interruptTraceFunction = new InterruptTraceFunction();

		// Setup __main__ module
		PyModule mod = imp.addModule("__main__");
		setLocals(mod.__dict__);

		// Load site.py (standard Python practice).
		// This will also load our sitecustomize.py module.
		imp.load("site");

		// Setup code completion module.
		// Note that this is not exported to the global address space by default.
		introspectModule = (PyModule) imp.load("jintrospect");

		// Add __builtin__ module for code completion
		builtinModule = (PyModule) imp.load("__builtin__");

		initializePythonPath();
	}

	/**
	 * Initializes/resets the python path to include all known Ghidra script paths.
	 */
	private void initializePythonPath() {

		// Restore the python path back to default.
		systemState.path.retainAll(defaultPythonPath);

		// Add in Ghidra script source directories
		for (ResourceFile resourceFile : GhidraScriptUtil.getScriptSourceDirectories()) {
			systemState.path.append(Py.newStringOrUnicode(resourceFile.getFile(false).getAbsolutePath()));
		}

		for (ResourceFile resourceFile : GhidraScriptUtil.getExplodedCompiledSourceBundlePaths()) {
			systemState.path.append(Py.newStringOrUnicode(resourceFile.getFile(false).getAbsolutePath()));
		}

		// Add in the PyDev remote debugger module
		if (!SystemUtilities.isInDevelopmentMode()) {
			File pyDevSrcDir = PyDevUtils.getPyDevSrcDir();
			if (pyDevSrcDir != null) {
				systemState.path.append(Py.newStringOrUnicode(pyDevSrcDir.getAbsolutePath()));
			}
		}
	}

	/**
	 * Pushes (executes) a line of Python to the interpreter.
	 *
	 * @param line the line of Python to push to the interpreter
	 * @param script a PythonScript from which we load state (or null)
	 * @return true if more input is needed before execution can occur
	 * @throws PyException if an unhandled exception occurred while executing the line of python
	 * @throws IllegalStateException if this interpreter has been cleaned up.
	 */
	public synchronized boolean push(String line, PythonScript script)
			throws PyException, IllegalStateException {

		if (cleanedUp) {
			throw new IllegalStateException(
				"Ghidra python interpreter has already been cleaned up.");
		}

		injectScriptHierarchy(script);

		if (buffer.length() > 0) {
			buffer.append("\n");
		}
		buffer.append(line);
		Py.getThreadState().tracefunc = interruptTraceFunction;
		Py.getSystemState().stderr = getSystemState().stderr; // needed to properly display SyntaxError
		boolean more;
		try {
			more = runsource(buffer.toString(), "python");
			getSystemState().stderr.invoke("flush");
			if (!more) {
				resetbuffer();
			}
		}
		catch (PyException pye) {
			resetbuffer();
			throw pye;
		}

		return more;
	}

	/**
	 * Execute a python file using this interpreter.
	 *
	 * @param file The python file to execute.
	 * @param script A PythonScript from which we load state (or null).
	 * @throws IllegalStateException if this interpreter has been cleaned up.
	 */
	public synchronized void execFile(ResourceFile file, PythonScript script)
			throws IllegalStateException {

		if (cleanedUp) {
			throw new IllegalStateException(
				"Ghidra python interpreter has already been cleaned up.");
		}

		injectScriptHierarchy(script);

		Py.getThreadState().tracefunc = interruptTraceFunction;

		// The Python import system sets the __file__ attribute to the file it's executing
		setVariable("__file__", new PyString(file.getAbsolutePath()));

		// If the remote python debugger is alive, initialize it by calling settrace()
		if (!SystemUtilities.isInDevelopmentMode() && !SystemUtilities.isInHeadlessMode()) {
			if (PyDevUtils.getPyDevSrcDir() != null) {
				try {
					InetAddress localhost = InetAddress.getLocalHost();
					new Socket(localhost, PyDevUtils.PYDEV_REMOTE_DEBUGGER_PORT).close();
					Msg.info(this, "Python debugger found");
					StringBuilder dbgCmds = new StringBuilder();
					dbgCmds.append("import pydevd;");
					dbgCmds.append("pydevd.threadingCurrentThread().__pydevd_main_thread = True;");
					dbgCmds.append("pydevd.settrace(host=\"" + localhost.getHostName() +
						"\", port=" + PyDevUtils.PYDEV_REMOTE_DEBUGGER_PORT + ", suspend=False);");
					exec(dbgCmds.toString());
					Msg.info(this, "Connected to a python debugger.");
				}
				catch (IOException e) {
					Msg.info(this, "Not connected to a python debugger.");
				}
			}
		}

		// Run python file
		execfile(file.getAbsolutePath());
	}

	@Override
	public synchronized void cleanup() {
		super.cleanup();
		cleanedUp = true;
	}

	/**
	 * Prints the given string to the interpreter's error stream with a newline
	 * appended.
	 *
	 * @param str The string to print.
	 */
	void printErr(String str) {
		try {
			getSystemState().stderr.invoke("write", new PyString(str + "\n"));
			getSystemState().stderr.invoke("flush");
		}
		catch (PyException e) {
			// if the python interp state's stdin/stdout/stderr is messed up, it can throw an error 
			Msg.error(this, "Failed to write to stderr", e);
		}
	}

	/**
	 * Gets the interpreter's primary prompt.
	 *
	 * @return The interpreter's primary prompt.
	 */
	synchronized String getPrimaryPrompt() {
		return getSystemState().ps1.toString();
	}

	/**
	 * Gets the interprester's secondary prompt.
	 *
	 * @return The interpreter's secondary prompt.
	 */
	synchronized String getSecondaryPrompt() {
		return getSystemState().ps2.toString();
	}

	/**
	 * Handle a KeyboardInterrupt.
	 * <p>
	 * This will attempt to interrupt the interpreter if it is running. There are
	 * two types of things this interrupt will work on:
	 * <p>
	 * 1: A batched series of python commands (such as a loop).  This works by setting
	 * our interrupt flag that is checked by our {@link InterruptTraceFunction} when
	 * various trace events happen.
	 * <p>
	 * 2: A sleeping or otherwise interruptible python command.  Since jython is all
	 * java under the hood, a sleep is really just a {@link Thread#sleep}, which we can
	 * kick with a {@link Thread#interrupt()}.
	 * <p>
	 * If another type of thing is taking a really long time, this interrupt will fail.
	 *
	 * @param pythonThread The Python Thread we need to interrupt.
	 */
	void interrupt(Thread pythonThread) {
		final long INTERRUPT_TIMEOUT = 5000;

		if ((pythonThread != null) && pythonThread.isAlive()) {

			// Set trace interrupt flag
			interrupt = Py.KeyboardInterrupt;

			// Wake potentially sleeping python command
			pythonThread.interrupt();

			try {
				pythonThread.join(INTERRUPT_TIMEOUT);
				if (pythonThread.isAlive()) {
					printErr("Cannot interrupt running command");
				}
			}
			catch (InterruptedException e) {
				// Nothing to do
			}
			interrupt = null;
		}
		else {
			printErr("KeyboardInterrupt");
		}
		resetbuffer();
	}

	/**
	 * Injects all of the accessible fields and methods found in the PythonScript class hierarchy into
	 * the given interpreter's Python address space.
	 *
	 * @param script The script whose class hierarchy is to be used for injection.
	 */
	private void injectScriptHierarchy(PythonScript script) {

		if (script == null) {
			return;
		}

		// Loop though the script class hierarchy
		for (Class<?> scriptClass = script.getClass(); scriptClass != Object.class; scriptClass =
			scriptClass.getSuperclass()) {

			// Add public and protected fields
			for (Field field : scriptClass.getDeclaredFields()) {
				if (Modifier.isPublic(field.getModifiers()) ||
					Modifier.isProtected(field.getModifiers())) {
					try {
						field.setAccessible(true);
						setVariable(field.getName(), field.get(script));
					}
					catch (IllegalAccessException iae) {
						throw new AssertException("Unexpected security manager being used!");
					}
				}
			}

			// Add public methods (only once). Ignore inner classes.
			//
			// NOTE: We currently do not have a way to safely add protected methods.  Disabling
			// python.security.respectJavaAccessibility and adding in protected methods in the below
			// loop caused an InaccessibleObjectException for some users (relating to core Java 
			// modules, not the GhidraScript class hierarchy).
			if (!scriptMethodsInjected) {
				for (Method method : scriptClass.getDeclaredMethods()) {
					if (!method.getName().contains("$") &&
						Modifier.isPublic(method.getModifiers())) {
						method.setAccessible(true);
						setMethod(script, method);
					}
				}
			}
		}

		scriptMethodsInjected = true;
	}

	/**
	 * Safely sets a variable in the interpreter's namespace. This first checks to
	 * make sure that we are not overriding a builtin Python symbol.
	 *
	 * @param varName The name of variable.
	 * @param obj The value of the variable.
	 * @return True if the variable was set; false if it already existed and wasn't set.
	 */
	private boolean setVariable(String varName, Object obj) {
		if (builtinModule.__findattr__(varName) == null) {
			set(varName, obj);
			return true;
		}
		return false;
	}

	/**
	 * Sets a bound (callback/function pointer) method as a local variable in the interpreter.
	 *
	 * @param obj A Java object that contains the method to bind.
	 * @param method The method from the object to bind.
	 * @return True if the method was set; false if it already existed and wasn't set.
	 */
	private boolean setMethod(Object obj, Method method) {
		String methodName = method.getName();

		// First, check to make sure we're not shadowing any internal Python keywords/functions/etc
		if (builtinModule.__findattr__(methodName) != null) {
			return false;
		}

		// OK, we're safe to set it
		PyObject pyObj = get(methodName);
		if ((null == pyObj) || (pyObj instanceof PyNone)) {
			// This is the first method of this name that we are adding. Create a new bound PyMethod
			// to bind the Java method to the Java object in the Python world.
			set(methodName, new PyMethod(new PyReflectedFunction(method), Py.java2py(obj),
				Py.java2py(obj.getClass())));
		}
		else if (pyObj instanceof PyMethod) {
			// Another method of this name has already been added. Add it to the list of possibilities
			// (different arguments to methods on the same Object). But first, we must do some sanity
			// checks.
			PyMethod pyMethod = (PyMethod) pyObj;
			if ((pyMethod.__self__._is(Py.java2py(obj))) != Py.True) {
				Msg.error(this,
					"Method " + methodName + " of " + obj + " attempting to shadow method " +
						pyMethod.__func__ + " of " + pyMethod.__self__);
				return false;
			}
			if (!(pyMethod.__func__ instanceof PyReflectedFunction)) {
				Msg.error(this, "For addition of method " + methodName + " of " + obj +
					", cannot mix with non Java function " + pyMethod.__func__);
				return false;
			}
			((PyReflectedFunction) pyMethod.__func__).addMethod(method);
		}

		return true;
	}

	/**
	 * Returns the possible command completions for a command.
	 *
	 * @param cmd The command line.
	 * @param includeBuiltins True if we should include python built-ins; otherwise, false.
	 * @return A list of possible command completions.  Could be empty if there aren't any.
	 * @see PythonPlugin#getCompletions
	 */
	List<CodeCompletion> getCommandCompletions(String cmd, boolean includeBuiltins) {
		if ((cmd.length() > 0) && (cmd.charAt(cmd.length() - 1) == '(')) {
			return getMethodCommandCompletions(cmd);
		}
		return getPropertyCommandCompletions(cmd, includeBuiltins);
	}

	/**
	 * Returns method documentation for the current command.
	 *
	 * @param cmd the current command
	 * @return method documentation for the current command
	 */
	private List<CodeCompletion> getMethodCommandCompletions(String cmd) {
		List<CodeCompletion> completion_list = new ArrayList<>();
		try {
			PyObject getCallTipJava = introspectModule.__findattr__("getCallTipJava");
			PyString command = new PyString(cmd);
			PyObject locals = getLocals();

			// Return value is (name, argspec, tip_text)
			ListIterator<?> iter =
				((List<?>) getCallTipJava.__call__(command, locals)).listIterator();
			while (iter.hasNext()) {
				String completion_portion = iter.next().toString();
				if (!completion_portion.equals("")) {
					String[] substrings = completion_portion.split("\n");
					for (String substring : substrings) {
						completion_list.add(new CodeCompletion(substring, null, null));
					}
				}
			}
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
		return completion_list;
	}

	/**
	 * Returns a Map of property-&gt;string_substitution pairs.
	 *
	 * @param cmd current command
	 * @param includeBuiltins True if we should include python built-ins; otherwise, false.
	 * @return A list of possible command completions.  Could be empty if there aren't any.
	 */
	private List<CodeCompletion> getPropertyCommandCompletions(String cmd,
			boolean includeBuiltins) {
		try {
			PyObject getAutoCompleteList = introspectModule.__findattr__("getAutoCompleteList");
			PyString command = new PyString(cmd);
			PyStringMap locals = ((PyStringMap) getLocals()).copy();
			if (includeBuiltins) {
				// Add in the __builtin__ module's contents for the search
				locals.update(builtinModule.__dict__);
			}
			List<?> list = (List<?>) getAutoCompleteList.__call__(command, locals);
			return CollectionUtils.asList(list, CodeCompletion.class);
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			return Collections.emptyList();
		}
	}

	/**
	 * Custom trace function that allows interruption of python code to occur when various code
	 * paths are encountered.
	 */
	class InterruptTraceFunction extends TraceFunction {
		private void checkInterrupt() {
			if (interrupt != null) {
				throw Py.makeException(interrupt);
			}
		}

		@Override
		public TraceFunction traceCall(PyFrame frame) {
			checkInterrupt();
			return this;
		}

		@Override
		public TraceFunction traceReturn(PyFrame frame, PyObject ret) {
			checkInterrupt();
			return this;
		}

		@Override
		public TraceFunction traceLine(PyFrame frame, int line) {
			checkInterrupt();
			return this;
		}

		@Override
		public TraceFunction traceException(PyFrame frame, PyException exc) {
			checkInterrupt();
			return this;
		}
	}
}
