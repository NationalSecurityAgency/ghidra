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

import java.io.*;
import java.util.concurrent.atomic.AtomicBoolean;

import ghidra.util.Msg;

/**
 * Thread responsible for getting interactive lines of python from the plugin.
 * This class also kicks off the execution of that line in a new {@link PythonPluginExecutionThread}.
 */
class PythonPluginInputThread extends Thread {

	private static int generationCount = 0;

	private final PythonPlugin plugin;
	private final AtomicBoolean moreInputWanted = new AtomicBoolean(false);
	private final AtomicBoolean shutdownRequested = new AtomicBoolean(false);
	private final InputStream consoleStdin;
	private PythonPluginExecutionThread pythonExecutionThread;

	/**
	 * Creates a new python input thread that gets a line of python input from the given plugin.
	 * 
	 * @param plugin The python plugin to get input from.
	 */
	PythonPluginInputThread(PythonPlugin plugin) {
		super("Python plugin input thread (generation " + ++generationCount + ")");
		this.plugin = plugin;
		this.consoleStdin = plugin.getConsole().getStdin();
	}

	/**
	 * Gets the last python plugin execution thread that ran.
	 * 
	 * @return The last python plugin execution thread that ran.  Could be null if one never ran.
	 */
	PythonPluginExecutionThread getPythonPluginExecutionThread() {
		return pythonExecutionThread;
	}

	@Override
	public void run() {
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(consoleStdin))) {
			String line;
			while (!shutdownRequested.get() && (line = reader.readLine()) != null) {

				// Execute the line in a new thread
				pythonExecutionThread =
					new PythonPluginExecutionThread(plugin, line, moreInputWanted);
				pythonExecutionThread.start();

				try {
					// Wait for the execution to finish
					pythonExecutionThread.join();
				}
				catch (InterruptedException ie) {
					// Hey we're back... a little earlier than expected, but there must be a reason. 
					// So we'll go quietly.
				}

				// Set the prompt appropriately
				plugin.getConsole()
						.setPrompt(
							moreInputWanted.get() ? plugin.getInterpreter().getSecondaryPrompt()
									: plugin.getInterpreter().getPrimaryPrompt());
			}
		}
		catch (IOException e) {
			Msg.error(PythonPluginInputThread.class,
				"Internal error reading commands from interpreter console.  Please reset the interpreter.",
				e);
		}
	}

	/**
	 * Causes the the background thread's run() loop to exit.
	 * <p>
	 * Causes background thread's exit by closing the inputstream it is looping on.
	 */
	void shutdown() {
		try {
			shutdownRequested.set(true);
			consoleStdin.close();
		}
		catch (IOException e) {
			// shouldn't happen, ignore
		}
	}
}
