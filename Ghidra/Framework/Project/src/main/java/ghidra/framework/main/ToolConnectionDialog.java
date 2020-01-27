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
package ghidra.framework.main;

import java.beans.PropertyChangeEvent;

import javax.swing.JButton;
import javax.swing.JPanel;

import docking.DialogComponentProvider;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

/**
 * Dialog to show existing connections between tools and
 * to connect tools.
 */
class ToolConnectionDialog extends DialogComponentProvider implements WorkspaceChangeListener {

	private ToolManager toolManager;
	private ToolConnectionPanel panel;
	private FrontEndTool frontEndTool;
	private final static String CONNECTALL = "Connect All";
	private final static String DISCONNECTALL = "Disconnect All";
	private JButton connectAllButton;
	private JButton disconnectAllButton;

	ToolConnectionDialog(FrontEndTool tool, ToolManager toolManager) {
		super("Connect Tools", false);
		this.frontEndTool = tool;
		this.toolManager = toolManager;
		setHelpLocation(new HelpLocation(GenericHelpTopics.FRONT_END, "Connect_Tools"));
		addWorkPanel(buildMainPanel());

		connectAllButton = new JButton(CONNECTALL);
		connectAllButton.addActionListener(ev -> connectCallback());
		addButton(connectAllButton);
		disconnectAllButton = new JButton(DISCONNECTALL);
		disconnectAllButton.addActionListener(ev -> disconnectCallback());
		addButton(disconnectAllButton);
		addOKButton();
		toolManager.addWorkspaceChangeListener(this);
	}

	void setVisible(boolean v) {

		if (v) {
			frontEndTool.showDialog(this);
			panel.showData();

			setStatusText("Please select an Event Producer");
			setConnectAllEnabled(false);
			setDisconnectAllEnabled(false);
		}
		else {
			close();
			toolManager.removeWorkspaceChangeListener(this);
			panel.clear();
		}
	}

	@Override
	public void toolAdded(Workspace ws, PluginTool tool) {
		panel.toolAdded(tool);
	}

	@Override
	public void toolRemoved(Workspace ws, PluginTool tool) {
		panel.toolRemoved(tool);
	}

	@Override
	protected void okCallback() {
		setVisible(false);
	}

	@Override
	public void workspaceAdded(Workspace ws) {
	}

	@Override
	public void workspaceRemoved(Workspace ws) {
	}

	@Override
	public void workspaceSetActive(Workspace ws) {
	}

	@Override
	public void propertyChange(PropertyChangeEvent event) {
		Object eventSource = event.getSource();
		if (eventSource instanceof PluginTool) {
			// tool name might have changed
			updateDisplay();
		}
	}

	void setToolManager(ToolManager tm) {
		toolManager.removeWorkspaceChangeListener(this);
		toolManager = tm;
		toolManager.addWorkspaceChangeListener(this);
		panel.setToolManager(toolManager);
	}

	/**
	 * Update the display because tools have been added or removed;
	 * restore selection if possible.
	 */
	void updateDisplay() {
		panel.updateDisplay();
	}

	void setConnectAllEnabled(boolean enabled) {
		connectAllButton.setEnabled(enabled);
	}

	void setDisconnectAllEnabled(boolean enabled) {
		disconnectAllButton.setEnabled(enabled);
	}

	/**
	 * Return the main panel for this dialog.
	 * The contents of this panel will be created in the constructor.
	 *
	 * @return JPanel
	 */
	protected JPanel buildMainPanel() {
		panel = new ToolConnectionPanel(this, toolManager);
		return panel;
	}

	/**
	 * "Connect All" button
	 */
	protected void connectCallback() {
		panel.connectAll(true);
	}

	/**
	 * "Disconnect All" button
	 */
	protected void disconnectCallback() {
		panel.connectAll(false);
	}

}
