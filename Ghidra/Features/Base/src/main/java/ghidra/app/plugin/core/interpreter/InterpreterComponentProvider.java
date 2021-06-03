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
package ghidra.app.plugin.core.interpreter;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;
import javax.swing.JComponent;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.OptionDialog;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.util.HelpLocation;
import resources.Icons;
import resources.ResourceManager;
import utility.function.Callback;

public class InterpreterComponentProvider extends ComponentProviderAdapter
		implements InterpreterConsole {

	private static final String CONSOLE_GIF = "images/monitor.png";
	private static final String CLEAR_GIF = "images/erase16.png";

	private InterpreterPanel panel;
	private InterpreterConnection interpreter;
	private List<Callback> firstActivationCallbacks;

	public InterpreterComponentProvider(InterpreterPanelPlugin plugin,
			InterpreterConnection interpreter, boolean visible) {
		super(plugin.getTool(), interpreter.getTitle(), plugin.getName());

		this.panel = new InterpreterPanel(plugin.getTool(), interpreter);
		this.interpreter = interpreter;
		this.firstActivationCallbacks = new ArrayList<>();

		setHelpLocation(new HelpLocation(getName(), "interpreter"));

		addToTool();
		createActions();

		Icon icon = interpreter.getIcon();
		if (icon == null) {
			icon = ResourceManager.loadImage(CONSOLE_GIF);
		}
		setIcon(icon);

		setVisible(visible);
	}

	private void createActions() {

		DockingAction clearAction = new DockingAction("Clear Interpreter", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				clear();
			}
		};
		clearAction.setDescription("Clear Interpreter");
		clearAction.setToolBarData(new ToolBarData(ResourceManager.loadImage(CLEAR_GIF), null));
		clearAction.setEnabled(true);

		addLocalAction(clearAction);
	}

	@Override
	public void addAction(DockingAction action) {
		addLocalAction(action);
	}

	/**
	 * Overridden so that we can add our custom actions for transient tools.
	 */
	@Override
	public void setTransient() {
		DockingAction disposeAction = new DockingAction("Remove Interpreter", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				int choice = OptionDialog.showYesNoDialog(panel, "Remove Interpreter?",
					"Are you sure you want to permanently close the interpreter?");
				if (choice == OptionDialog.NO_OPTION) {
					return;
				}

				InterpreterComponentProvider.this.dispose();
			}
		};
		disposeAction.setDescription("Remove interpreter from tool");
		disposeAction.setToolBarData(new ToolBarData(Icons.STOP_ICON, null));
		disposeAction.setEnabled(true);

		addLocalAction(disposeAction);
	}

	@Override
	public String getWindowSubMenuName() {
		return interpreter.getTitle();
	}

	@Override
	public String getTitle() {
		return interpreter.getTitle();
	}

	@Override
	public String getSubTitle() {
		return "Interpreter";
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	@Override
	public void clear() {
		panel.clear();
	}

	@Override
	public InputStream getStdin() {
		return panel.getStdin();
	}

	@Override
	public OutputStream getStdOut() {
		return panel.getStdOut();
	}

	@Override
	public OutputStream getStdErr() {
		return panel.getStdErr();
	}

	@Override
	public PrintWriter getOutWriter() {
		return panel.getOutWriter();
	}

	@Override
	public PrintWriter getErrWriter() {
		return panel.getErrWriter();
	}

	/**
	 * For testing purposes, but should probably be promoted to InterpreterConsole interface
	 * 
	 * @return the prompt;
	 */
	public String getPrompt() {
		return panel.getPrompt();
	}

	@Override
	public void setPrompt(String prompt) {
		panel.setPrompt(prompt);
	}

	@Override
	public void dispose() {
		removeFromTool();
		panel.dispose();
	}

	@Override
	public void componentActivated() {

		// Since we only care about the first activation, clear the list of callbacks so future 
		// activations don't trigger anything.  First save them off to a local list so when we
		// process them we aren't affected by concurrent modification due to reentrance.
		List<Callback> callbacks = new ArrayList<>(firstActivationCallbacks);
		firstActivationCallbacks.clear();

		// Call the callbacks
		callbacks.forEach(l -> l.call());
	}

	@Override
	public void addFirstActivationCallback(Callback activationCallback) {
		firstActivationCallbacks.add(activationCallback);
	}

	@Override
	public boolean isInputPermitted() {
		return panel.isInputPermitted();
	}

	@Override
	public void setInputPermitted(boolean permitted) {
		panel.setInputPermitted(permitted);
	}

	@Override
	public void show() {
		tool.showComponentProvider(this, true);
	}

	@Override
	public void updateTitle() {
		tool.updateTitle(this);
	}

	/**
	 * For testing purposes only
	 * 
	 * @return the text in the output buffer
	 */
	public String getOutputText() {
		return panel.getOutputText();
	}
}
