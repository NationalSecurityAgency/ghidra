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

import java.util.concurrent.atomic.AtomicBoolean;

import org.python.core.PyException;

/**
 * Thread responsible for executing a jython script from a file.
 */
class JythonScriptExecutionThread extends Thread {

	private JythonScript script;
	private GhidraJythonInterpreter interpreter;
	private AtomicBoolean interpreterRunning;

	/**
	 * Creates a new jython script execution thread that executes the given jython script.
	 * 
	 * @param script The jython script to execute.
	 * @param interpreter The jython interpreter to use for execution.
	 * @param interpreterRunning Gets set to indicate whether or not the interpreter is still running the script.
	 */
	JythonScriptExecutionThread(JythonScript script, GhidraJythonInterpreter interpreter,
			AtomicBoolean interpreterRunning) {
		super("Jython script execution thread");

		this.script = script;
		this.interpreter = interpreter;
		this.interpreterRunning = interpreterRunning;
	}

	@Override
	public void run() {

		try {
			interpreter.execFile(script.getSourceFile(), script);
		}
		catch (PyException pye) {
			if (PyException.exceptionClassName(pye.type).equalsIgnoreCase(
				"exceptions.SystemExit")) {
				interpreter.printErr("SystemExit");
			}
			else {
				pye.printStackTrace(); // this prints to the interpreter error stream.
			}
		}
		catch (StackOverflowError soe) {
			interpreter.printErr("Stack overflow!");
		}
		catch (IllegalStateException e) {
			interpreter.printErr(e.getMessage());
		}
		finally {
			interpreterRunning.set(false);
		}
	}
}
