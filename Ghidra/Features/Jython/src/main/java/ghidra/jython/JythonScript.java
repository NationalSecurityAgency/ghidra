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
package ghidra.jython;

import java.io.PrintWriter;
import java.util.concurrent.atomic.AtomicBoolean;

import generic.jar.ResourceFile;
import ghidra.app.script.*;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.exception.AssertException;

/**
 * A Jython version of a {@link GhidraScript}.
 */
public class JythonScript extends GhidraScript {

	static final String JYTHON_INTERPRETER = "ghidra.jython.interpreter";

	private AtomicBoolean interpreterRunning = new AtomicBoolean();

	@Override
	public void run() {

		// Try to get the interpreter from an existing script state.
		GhidraJythonInterpreter interpreter =
			(GhidraJythonInterpreter) state.getEnvironmentVar(JYTHON_INTERPRETER);

		// Are we being called from an already running JythonScript with existing state?
		if (interpreter != null) {
			runInExistingEnvironment(interpreter);
		}
		else {
			runInNewEnvironment();
		}
	}

	@Override
	public void runScript(String scriptName, GhidraState scriptState) throws Exception {
		GhidraJythonInterpreter interpreter =
			(GhidraJythonInterpreter) state.getEnvironmentVar(JYTHON_INTERPRETER);
		if (interpreter == null) {
			interpreter = GhidraJythonInterpreter.get();
			if (interpreter == null) {
				throw new AssertException("Could not get Ghidra Jython interpreter!");
			}
		}
		ResourceFile scriptSource = GhidraScriptUtil.findScriptByName(scriptName);
		if (scriptSource != null) {
			GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptSource);
			GhidraScript ghidraScript = provider.getScriptInstance(scriptSource, errorWriter);
			if (ghidraScript == null) {
				throw new IllegalArgumentException("Script does not exist: " + scriptName);
			}

			if (scriptState == state) {
				updateStateFromVariables();
			}

			if (ghidraScript instanceof JythonScript) {
				ghidraScript.set(scriptState);
				JythonScript jythonScript = (JythonScript) ghidraScript;
				interpreter.execFile(jythonScript.getSourceFile(), jythonScript);
			}
			else {
				ghidraScript.execute(scriptState, getControls());
			}

			if (scriptState == state) {
				loadVariablesFromState();
			}
			return;
		}
		throw new IllegalArgumentException("Script does not exist: " + scriptName);
	}

	/**
	 * Runs this script in an existing interpreter environment.
	 * 
	 * @param interpreter The existing interpreter to execute from.
	 */
	private void runInExistingEnvironment(GhidraJythonInterpreter interpreter) {
		interpreter.execFile(sourceFile, this);
	}

	/**
	 * Runs this script in a new interpreter environment and sticks the new interpreter
	 * in the script state so it can be retrieved by scripts called from this script.
	 */
	private void runInNewEnvironment() {

		// Create new interpreter and stick it in the script's state.
		final GhidraJythonInterpreter interpreter = GhidraJythonInterpreter.get();
		final PrintWriter stdout = getStdOut();
		final PrintWriter stderr = getStdErr();
		interpreter.setOut(stdout);
		interpreter.setErr(stderr);

		// We stick the interpreter in the state so that if the script calls runScript, that
		// script will use the same interpreter.  It is questionable whether or not we should do 
		// this (the new script will get all of the old script's variables), but changing it now
		// could break people's scripts if they expect this behavior.
		state.addEnvironmentVar(JYTHON_INTERPRETER, interpreter);

		// Execute the script in a new thread.
		JythonScriptExecutionThread executionThread =
			new JythonScriptExecutionThread(this, interpreter, interpreterRunning);
		interpreterRunning.set(true);
		executionThread.start();

		// Wait for the script be finish running
		while (interpreterRunning.get() && !monitor.isCancelled()) {
			Thread.yield();
			sleep100millis();
		}
		if (interpreterRunning.get()) {
			// We've been canceled. Interrupt the interpreter.
			interpreter.interrupt(executionThread);
		}

		// Script is done. Make sure the output displays.
		stderr.flush();
		stdout.flush();

		// Cleanup the interpreter, and remove it from the state (once it's cleaned it cannot be
		// reused)
		interpreter.cleanup();
		state.removeEnvironmentVar(JYTHON_INTERPRETER);
	}

	private PrintWriter getStdOut() {
		PluginTool tool = state.getTool();
		if (tool != null) {
			ConsoleService console = tool.getService(ConsoleService.class);
			if (console != null) {
				return console.getStdOut();
			}
		}
		return new PrintWriter(System.out, true);
	}

	private PrintWriter getStdErr() {
		PluginTool tool = state.getTool();
		if (tool != null) {
			ConsoleService console = tool.getService(ConsoleService.class);
			if (console != null) {
				return console.getStdErr();
			}
		}
		return new PrintWriter(System.err, true);
	}

	private void sleep100millis() {
		try {
			Thread.sleep(100);
		}
		catch (InterruptedException e) {
			// Don't care; will probably be called again
		}
	}

	@Override
	public String getCategory() {
		return "Jython";
	}
}
