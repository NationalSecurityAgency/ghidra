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
package ghidra.app.plugin.core.script;

import java.awt.BorderLayout;
import java.awt.Component;

import javax.swing.*;

import docking.*;
import docking.actions.ToolActions;
import docking.widgets.label.GLabel;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

class KeyBindingInputDialog extends DialogComponentProvider implements KeyEntryListener {
	private KeyEntryPanel kbPanel;
	private KeyStroke ks;
	private boolean isCancelled;
	private Plugin plugin;

	KeyBindingInputDialog(Component parent, String scriptName, KeyStroke currentKeyStroke,
			Plugin plugin, HelpLocation help) {
		super("Assign Script Key Binding", true, true, true, false);
		this.plugin = plugin;

		kbPanel = new KeyEntryPanel(20, this);
		if (currentKeyStroke != null) {
			kbPanel.setKeyStroke(currentKeyStroke);
		}

		JPanel panel = new JPanel(new BorderLayout(10, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(new GLabel(scriptName), BorderLayout.NORTH);
		panel.add(kbPanel, BorderLayout.CENTER);

		addWorkPanel(panel);
		addOKButton();
		addCancelButton();
		setHelpLocation(help);

		DockingWindowManager.showDialog(parent, this);
	}

	@Override
	protected void okCallback() {
		PluginTool tool = plugin.getTool();
		ToolActions toolActions = (ToolActions) tool.getToolActions();
		String errorMessage = toolActions.validateActionKeyBinding(null, ks);
		if (errorMessage != null) {
			setStatusText(errorMessage);
			return;
		}

		close();
	}

	@Override
	protected void cancelCallback() {
		super.cancelCallback();
		isCancelled = true;
	}

	boolean isCancelled() {
		return isCancelled;
	}

	@Override
	public void processEntry(KeyStroke keyStroke) {
		ks = keyStroke;
	}

	KeyStroke getKeyStroke() {
		return ks;
	}

	void setKeyStroke(KeyStroke ks) {
		this.ks = ks;
		kbPanel.setKeyStroke(ks);
	}
}
