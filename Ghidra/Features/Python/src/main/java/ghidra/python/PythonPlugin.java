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

import java.awt.event.KeyEvent;
import java.io.*;
import java.util.List;

import javax.swing.ImageIcon;

import org.python.core.PySystemState;

import docking.ActionContext;
import docking.DockingUtils;
import docking.action.*;
import generic.jar.ResourceFile;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.*;
import ghidra.app.script.GhidraState;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.task.*;
import resources.ResourceManager;

/**
 * This plugin provides the interactive Python interpreter.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.INTERPRETERS,
	shortDescription = "Python Interpreter",
	description = "Provides an interactive Python Interpreter that is tightly integrated with a loaded Ghidra program.",
	servicesRequired = { InterpreterPanelService.class },
	isSlowInstallation = true
)
//@formatter:on
public class PythonPlugin extends ProgramPlugin
		implements InterpreterConnection, OptionsChangeListener {

	private final static int INPUT_THREAD_SHUTDOWN_TIMEOUT_MS = 1000;

	private InterpreterConsole console;
	private GhidraPythonInterpreter interpreter;
	private PythonScript interactiveScript;
	private TaskMonitor interactiveTaskMonitor;
	private PythonPluginInputThread inputThread;

	// Plugin options
	private final static String INCLUDE_BUILTINS_LABEL = "Include \"builtins\" in code completion?";
	private final static String INCLUDE_BUILTINS_DESCRIPTION =
		"Whether or not to include Python's built-in functions and properties in the pop-up code completion window.";
	private final static boolean INCLUDE_BUILTINS_DEFAULT = true;
	private boolean includeBuiltins = INCLUDE_BUILTINS_DEFAULT;

	/**
	 * Creates a new PythonPlugin object.
	 * 
	 * @param tool The tool associated with this plugin.
	 */
	public PythonPlugin(PluginTool tool) {
		super(tool, true, true, true);
	}

	/**
	 * Gets the plugin's interpreter console.
	 * 
	 * @return The plugin's interpreter console.
	 */
	InterpreterConsole getConsole() {
		return console;
	}

	/**
	 * Gets the plugin's Python interpreter.
	 * 
	 * @return The plugin's Python interpreter.  May be null.
	 */
	GhidraPythonInterpreter getInterpreter() {
		return interpreter;
	}

	/**
	 * Gets the plugin's interactive script
	 * 
	 * @return The plugin's interactive script.
	 */
	PythonScript getInteractiveScript() {
		return interactiveScript;
	}

	/**
	 * Gets the plugin's interactive task monitor.
	 * 
	 * @return The plugin's interactive task monitor.
	 */
	TaskMonitor getInteractiveTaskMonitor() {
		return interactiveTaskMonitor;
	}

	@Override
	protected void init() {
		super.init();

		console =
			getTool().getService(InterpreterPanelService.class).createInterpreterPanel(this, false);
		welcome();
		console.addFirstActivationCallback(() -> resetInterpreter());
		createActions();
	}

	/**
	 * Creates various actions for the plugin.
	 */
	private void createActions() {
		
		// Interrupt Interpreter
		DockingAction interruptAction = new DockingAction("Interrupt Interpreter", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				interrupt();
			}
		};
		interruptAction.setDescription("Interrupt Interpreter");
		interruptAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/dialog-cancel.png"), null));
		interruptAction.setEnabled(true);
		interruptAction.setKeyBindingData(
			new KeyBindingData(KeyEvent.VK_I, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
		interruptAction.setHelpLocation(new HelpLocation(getTitle(), "Interrupt_Interpreter"));
		console.addAction(interruptAction);

		// Reset Interpreter
		DockingAction resetAction = new DockingAction("Reset Interpreter", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				reset();
			}
		};
		resetAction.setDescription("Reset Interpreter");
		resetAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/reload3.png"), null));
		resetAction.setEnabled(true);
		resetAction.setKeyBindingData(
			new KeyBindingData(KeyEvent.VK_D, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
		resetAction.setHelpLocation(new HelpLocation(getTitle(), "Reset_Interpreter"));
		console.addAction(resetAction);
	}

	/**
	 * Resets the interpreter to a new starting state.  This is used when the plugin is first
	 * initialized, as well as when an existing interpreter receives a Python exit command.
	 * We used to try to reset the same interpreter, but it was really hard to do that correctly
	 * so we now just create a brand new one.
	 * <p>
	 * NOTE: Loading Jython for the first time can be quite slow the first time, so we do this
	 * when the user wants to first interact with the interpreter (rather than when the plugin loads).
	 */
	private void resetInterpreter() {

		TaskLauncher.launchModal("Resetting Python...", () -> {
			resetInterpreterInBackground();
		});
	}

	// we expect this to be called from off the Swing thread
	private void resetInterpreterInBackground() {

		//  Reset the interpreter by creating a new one. Clean up the old one if present.
		if (interpreter == null) {

			// Setup options
			ToolOptions options = tool.getOptions("Python");
			includeBuiltins = options.getBoolean(INCLUDE_BUILTINS_LABEL, INCLUDE_BUILTINS_DEFAULT);
			options.registerOption(INCLUDE_BUILTINS_LABEL, INCLUDE_BUILTINS_DEFAULT, null,
				INCLUDE_BUILTINS_DESCRIPTION);
			options.addOptionsChangeListener(this);

			interpreter = GhidraPythonInterpreter.get();

			// Setup code completion.  This currently has to be done after the interpreter
			// is created.  Otherwise an exception will occur.
			PythonCodeCompletionFactory.setupOptions(this, options);
		}
		else {
			inputThread.shutdown();
			inputThread = null;
			interpreter.cleanup();
			interpreter = GhidraPythonInterpreter.get();
		}

		// Reset the console.
		console.clear();
		console.setPrompt(interpreter.getPrimaryPrompt());

		// Tie the interpreter's input/output to the plugin's console.
		interpreter.setIn(console.getStdin());
		interpreter.setOut(console.getStdOut());
		interpreter.setErr(console.getStdErr());

		// Print a welcome message.
		welcome();

		// Setup the PythonScript describing the state of the interactive prompt.
		// This allows things like currentProgram and currentAddress to dynamically reflect
		// what's happening in the listing.
		interactiveScript = new PythonScript();
		interactiveTaskMonitor = new PythonInteractiveTaskMonitor(console.getStdOut());

		// Start the input thread that receives python commands to execute.
		inputThread = new PythonPluginInputThread(this);
		inputThread.start();
	}

	/**
	 * Handle a change in one of our options.
	 * 
	 * @param options the options handle
	 * @param optionName name of the option changed
	 * @param oldValue the old value
	 * @param newValue the new value
	 */
	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		if (optionName.startsWith(PythonCodeCompletionFactory.COMPLETION_LABEL)) {
			PythonCodeCompletionFactory.changeOptions(options, optionName, oldValue, newValue);
		}
		else if (optionName.equals(PythonCodeCompletionFactory.INCLUDE_TYPES_LABEL)) {
			PythonCodeCompletionFactory.changeOptions(options, optionName, oldValue, newValue);
		}
		else if (optionName.equals(INCLUDE_BUILTINS_LABEL)) {
			includeBuiltins = ((Boolean) newValue).booleanValue();
		}
	}

	/**
	 * Returns a list of possible command completion values.
	 * 
	 * @param cmd current command line (without prompt)
	 * @return A list of possible command completion values.  Could be empty if there aren't any.
	 */
	@Override
	public List<CodeCompletion> getCompletions(String cmd) {
		// Refresh the environment
		interactiveScript.setSourceFile(new ResourceFile(new File("python")));
		interactiveScript.set(
			new GhidraState(tool, tool.getProject(), currentProgram, currentLocation,
				currentSelection, currentHighlight),
			interactiveTaskMonitor, console.getOutWriter());

		return interpreter.getCommandCompletions(cmd, includeBuiltins);
	}

	@Override
	protected void dispose() {

		// Do an interrupt in case there is a loop or something running
		interrupt();

		// Terminate the input thread
		if (inputThread != null) {
			inputThread.shutdown();
			inputThread = null;
		}

		// Dispose of the console
		if (console != null) {
			console.dispose();
			console = null;
		}

		// Cleanup the interpreter
		if (interpreter != null) {
			interpreter.cleanup();
			interpreter = null;
		}

		super.dispose();
	}

	/**
	 * Interrupts what the interpreter is currently doing.
	 */
	public void interrupt() {
		if (interpreter == null) {
			return;
		}
		interpreter.interrupt(inputThread.getPythonPluginExecutionThread());
		console.setPrompt(interpreter.getPrimaryPrompt());
	}

	/**
	 * Resets the interpreter's state.
	 */
	public void reset() {

		// Do an interrupt in case there is a loop or something running
		interrupt();

		resetInterpreter();
	}

	@Override
	public String getTitle() {
		return "Python";
	}

	@Override
	public String toString() {
		return getPluginDescription().getName();
	}

	@Override
	public ImageIcon getIcon() {
		return ResourceManager.loadImage("images/python.png");
	}

	/**
	 * Prints a welcome message to the console.
	 */
	private void welcome() {
		console.getOutWriter().println("Python Interpreter for Ghidra");
		console.getOutWriter().println("Based on Jython version " + PySystemState.version);
		console.getOutWriter().println("Press 'F1' for usage instructions");
	}

	/**
	 * Support for cancelling execution using a TaskMonitor.
	 */
	class PythonInteractiveTaskMonitor extends TaskMonitorAdapter {
		private PrintWriter output = null;

		public PythonInteractiveTaskMonitor(PrintWriter stdOut) {
			output = stdOut;
		}

		public PythonInteractiveTaskMonitor(OutputStream stdout) {
			this(new PrintWriter(stdout));
		}

		@Override
		public void setMessage(String message) {
			output.println("<python-interactive>: " + message);
		}
	}
}
