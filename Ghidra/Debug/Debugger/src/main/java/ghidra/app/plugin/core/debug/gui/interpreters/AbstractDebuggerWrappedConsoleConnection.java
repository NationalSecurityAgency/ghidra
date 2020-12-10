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
package ghidra.app.plugin.core.debug.gui.interpreters;

import java.io.*;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.ImageIcon;

import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.target.TargetConsole.TargetConsoleListener;
import ghidra.dbg.target.TargetInterpreter;
import ghidra.dbg.target.TargetInterpreter.TargetInterpreterListener;
import ghidra.dbg.target.TargetObject;
import ghidra.util.Msg;

public abstract class AbstractDebuggerWrappedConsoleConnection<T extends TargetObject>
		implements InterpreterConnection {

	/**
	 * We inherit console text output from interpreter listener, even though we may be listening to
	 * a plain console.
	 */
	protected class ForInterpreterListener implements TargetInterpreterListener {
		@Override
		public void consoleOutput(TargetObject console, Channel channel, String out) {
			switch (channel) {
				case STDOUT:
					if (outWriter == null) {
						return;
					}
					outWriter.print(out);
					outWriter.flush();
					break;
				case STDERR:
					if (errWriter == null) {
						return;
					}
					errWriter.print(out);
					errWriter.flush();
					break;
			}
		}

		@Override
		public void displayChanged(TargetObject object, String display) {
			guiConsole.updateTitle();
		}

		@Override
		public void promptChanged(TargetInterpreter<?> i, String prompt) {
			guiConsole.setPrompt(prompt);
		}

		@Override
		public void invalidated(TargetObject object, String reason) {
			if (object == targetConsole) { // Redundant
				running.set(false);
				plugin.disableConsole(targetConsole, guiConsole);
			}
		}
	}

	protected final DebuggerInterpreterPlugin plugin;
	protected final T targetConsole;

	protected final AtomicBoolean running = new AtomicBoolean(false);
	protected final TargetConsoleListener listener = new ForInterpreterListener();
	protected Thread thread;
	protected InterpreterConsole guiConsole;
	protected BufferedReader inReader;
	protected PrintWriter outWriter;
	protected PrintWriter errWriter;

	public AbstractDebuggerWrappedConsoleConnection(DebuggerInterpreterPlugin plugin,
			T targetConsole) {
		this.plugin = plugin;
		this.targetConsole = targetConsole;
		targetConsole.addListener(listener);
	}

	protected abstract CompletableFuture<Void> sendLine(String line);

	@Override
	public String getTitle() {
		return "Interpreter: " + targetConsole.getDisplay();
	}

	@Override
	public ImageIcon getIcon() {
		return DebuggerResources.ICON_CONSOLE;
	}

	@Override
	public List<CodeCompletion> getCompletions(String cmd) {
		// TODO: If GDB or WinDBG ever provides an API for completion....
		return Collections.emptyList();
	}

	public void setConsole(InterpreterConsole guiConsole) {
		this.guiConsole = guiConsole;
		setErrWriter(guiConsole.getErrWriter());
		setOutWriter(guiConsole.getOutWriter());
		setStdIn(guiConsole.getStdin());
	}

	public void setOutWriter(PrintWriter outWriter) {
		this.outWriter = outWriter;
	}

	public void setErrWriter(PrintWriter errWriter) {
		this.errWriter = errWriter;
	}

	public void setStdIn(InputStream stdIn) {
		this.inReader = new BufferedReader(new InputStreamReader(stdIn));
	}

	public void runInBackground() {
		running.set(true);
		thread = new Thread(this::run);
		thread.start();
	}

	protected void run() {
		try {
			while (running.get()) {
				String line = inReader.readLine();
				if (!running.get()) {
					return;
				}
				sendLine(line).exceptionally(e -> {
					/**
					 * Do not print such errors to the console. The model ought to output an error,
					 * but in case the exception is not from the user typing an invalid command, we
					 * ought to log it for debugging.
					 */
					Msg.debug(this, "Debugger console exception sending '" + line + "'", e);
					return null;
				});
			}
		}
		catch (IOException e) {
			Msg.debug(this, "Lost console?");
		}
	}
}
