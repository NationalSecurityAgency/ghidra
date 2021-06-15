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
import java.lang.invoke.MethodHandles;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.InterpreterInterruptAction;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.PinInterpreterAction;
import ghidra.app.plugin.core.interpreter.InterpreterComponentProvider;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.dbg.AnnotatedDebuggerAttributeListener;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.util.Msg;
import ghidra.util.Swing;

public abstract class AbstractDebuggerWrappedConsoleConnection<T extends TargetObject>
		implements DebuggerInterpreterConnection {

	/**
	 * We inherit console text output from interpreter listener, even though we may be listening to
	 * a plain console.
	 */
	protected class ForInterpreterListener extends AnnotatedDebuggerAttributeListener {
		public ForInterpreterListener() {
			super(MethodHandles.lookup());
		}

		@Override
		public void consoleOutput(TargetObject console, Channel channel, byte[] out) {
			OutputStream os;
			switch (channel) {
				case STDOUT:
					os = stdOut;
					break;
				case STDERR:
					os = stdErr;
					break;
				default:
					throw new AssertionError();
			}
			// It's possible stdOut/Err was not initialized, yet
			if (os == null) {
				return;
			}
			/**
			 * NB: yes, the extra space is lame... The InterpreterPanel's repositionScrollPane
			 * method subtracts 1 from the text length to compute the new position causing it to
			 * scroll to the last character printed. We want it to scroll to the next line, so...
			 */
			try {
				os.write(out);
				os.write(' ');
			}
			catch (IOException e) {
				Msg.error(this, "Cannot write to interpreter window: ", e);
			}
		}

		@AttributeCallback(TargetObject.DISPLAY_ATTRIBUTE_NAME)
		public void displayChanged(TargetObject object, String display) {
			// TODO: Add setSubTitle(String) to InterpreterConsole
			if (guiConsole == null) {
				/**
				 * Can happen during init. setSubTitle will get called immediately after guiConsole
				 * is initialized.
				 */
				return;
			}
			InterpreterComponentProvider provider = (InterpreterComponentProvider) guiConsole;
			Swing.runLater(() -> provider.setSubTitle(display));
		}

		@AttributeCallback(TargetInterpreter.PROMPT_ATTRIBUTE_NAME)
		public void promptChanged(TargetObject interpreter, String prompt) {
			if (guiConsole == null) {
				/**
				 * Can happen during init. setPrompt will get called immediately after guiConsole is
				 * initialized. NB. It happens in DebuggerWrappedInterpreterConnection
				 */
				return;
			}
			Swing.runLater(() -> guiConsole.setPrompt(prompt));
		}

		@Override
		public void invalidated(TargetObject object, TargetObject branch, String reason) {
			Swing.runLater(() -> {
				if (object == targetConsole) { // Redundant
					consoleInvalidated();
				}
			});
		}
	}

	protected final DebuggerInterpreterPlugin plugin;
	protected final T targetConsole;

	protected final AtomicBoolean running = new AtomicBoolean(false);
	protected final ForInterpreterListener listener = new ForInterpreterListener();
	protected Thread thread;
	protected InterpreterConsole guiConsole;
	protected BufferedReader inReader;
	protected OutputStream stdOut;
	protected OutputStream stdErr;

	protected ToggleDockingAction actionPin;
	protected boolean pinned = false;

	public AbstractDebuggerWrappedConsoleConnection(DebuggerInterpreterPlugin plugin,
			T targetConsole) {
		this.plugin = plugin;
		this.targetConsole = targetConsole;
		targetConsole.addListener(listener);
	}

	protected abstract CompletableFuture<Void> sendLine(String line);

	@Override
	public String getTitle() {
		return DebuggerResources.TITLE_PROVIDER_INTERPRETER;
	}

	@Override
	public ImageIcon getIcon() {
		return DebuggerResources.ICON_CONSOLE;
	}

	@Override
	public List<CodeCompletion> getCompletions(String cmd) {
		// TODO: If GDB or WinDBG ever provides an API for completion....
		// TODO: Of course, that's another method on TargetInterpeter, too.
		return Collections.emptyList();
	}

	public void setConsole(InterpreterConsole guiConsole) {
		assert this.guiConsole == null;
		this.guiConsole = guiConsole;

		InterpreterComponentProvider provider = (InterpreterComponentProvider) guiConsole;
		provider.setSubTitle(targetConsole.getDisplay());

		setStdErr(guiConsole.getStdErr());
		setStdOut(guiConsole.getStdOut());
		setStdIn(guiConsole.getStdin());

		createActions();

		if (!targetConsole.isValid()) {
			consoleInvalidated();
		}
	}

	protected void consoleInvalidated() {
		if (pinned) {
			running.set(false);
			plugin.disableConsole(targetConsole, guiConsole);
		}
		else {
			plugin.destroyConsole(targetConsole, guiConsole);
		}
	}

	protected void createActions() {
		actionPin = PinInterpreterAction.builder(plugin)
				.onAction(this::activatedPin)
				.selected(pinned)
				.build();
		guiConsole.addAction(actionPin);

		DockingAction interruptAction =	InterpreterInterruptAction.builder(plugin)
				.onAction(this::sendInterrupt)
				.build();
		guiConsole.addAction(interruptAction);
	}

	public void setStdOut(OutputStream stdOut) {
		this.stdOut = stdOut;
	}

	public void setStdErr(OutputStream stdErr) {
		this.stdErr = stdErr;
	}

	public void setStdIn(InputStream stdIn) {
		this.inReader = new BufferedReader(new InputStreamReader(stdIn));
	}

	public void runInBackground() {
		running.set(true);
		thread = new Thread(this::run);
		thread.start();
	}

	private void activatedPin(ActionContext ignore) {
		pinned = actionPin.isSelected();
	}

	private void sendInterrupt(ActionContext ignore) {
		CompletableFuture<TargetInterruptible> futureInterruptible =
			DebugModelConventions.suitable(TargetInterruptible.class, targetConsole);
		if (futureInterruptible != null) {
			futureInterruptible.thenCompose(i -> i.interrupt())
					.thenRun(() -> guiConsole.getOutWriter().println("Interrupt sent"))
					.exceptionally(exc -> {
						guiConsole.getErrWriter().println("Failed to send Interrupt");
						return null;
					});
		}
	}

	protected void run() {
		try {
			while (running.get()) {
				String line = inReader.readLine();
				if (line == null || !running.get()) {
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

	@Override
	public InterpreterConsole getInterpreterConsole() {
		return guiConsole;
	}

	@Override
	public TargetObject getTargetConsole() {
		return targetConsole;
	}

	@Override
	public boolean isPinned() {
		return pinned;
	}

	@Override
	public void setPinned(boolean pinned) {
		this.pinned = pinned;
		actionPin.setSelected(pinned);
	}
}
