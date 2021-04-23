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
package ghidra.dbg.testutil;

import java.io.*;

import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.target.TargetInterpreter;
import ghidra.dbg.target.TargetObject;

public class DebuggerConsole extends Thread implements DebuggerModelListener, AutoCloseable {
	private final DebuggerObjectModel model;
	private final BufferedReader reader;

	private TargetInterpreter interpreter;
	private boolean closed = false;

	public DebuggerConsole(DebuggerObjectModel model) {
		this.model = model;
		this.reader = new BufferedReader(new InputStreamReader(System.in));

		model.addModelListener(this);
		setDaemon(true);
		start();
	}

	@Override
	public void consoleOutput(TargetObject console, Channel channel, byte[] data) {
		if (console instanceof TargetInterpreter) {
			if (interpreter == null) {
				System.out.println("Found interpreter: " + console);
				interpreter = (TargetInterpreter) console;
			}
		}
		String text = new String(data);
		System.out.println(text);
	}

	@Override
	public void run() {
		try {
			while (!closed) {
				String line = reader.readLine();
				if (line == null) {
					// NB. EOF happens immediately under Gradle
					return;
				}
				if (interpreter == null) {
					System.err.println("Have not found interpreter, yet");
					continue;
				}
				interpreter.execute(line).whenComplete((__, ex) -> {
					if (ex != null) {
						System.err.println("Command error: " + ex.getMessage());
					}
					else {
						System.out.println("Command finished");
					}
				});
			}
		}
		catch (IOException e) {
			System.err.println("IOException on console: " + e);
		}
	}

	@Override
	public void close() throws Exception {
		model.removeModelListener(this);
		closed = true;
		interrupt();
	}
}
