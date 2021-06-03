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

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.HashMap;
import java.util.Map;

import javax.swing.*;

import docking.DockingUtils;
import ghidra.framework.model.ToolTemplate;
import ghidra.framework.model.Workspace;
import ghidra.framework.plugintool.PluginTool;

class RunningToolsPanel extends JPanel {
	private JToolBar runningToolbar;
	private FrontEndPlugin plugin;
	private Map<PluginTool, ToolButton> runningTools;

	RunningToolsPanel(FrontEndPlugin plugin, Workspace ws) {
		super(new BorderLayout(0, 0));
		this.plugin = plugin;

		runningToolbar = new JToolBar(SwingConstants.HORIZONTAL) {
			// don't let the user accidentally drag the tools out
			// of the workspace panel
			@Override
			public boolean isFloatable() {
				return false;
			}

			@Override
			public boolean isBorderPainted() {
				return false;
			}
		};

		// let the default coloring shine through this toolbar; leaving this opaque causes
		// odd display coloring issues in some LookAndFeels, like Metal
		DockingUtils.setTransparent(runningToolbar);

		// remove the default etched border
		add(runningToolbar, BorderLayout.CENTER);

		runningTools =
			new HashMap<PluginTool, ToolButton>(WorkspacePanel.TYPICAL_NUM_RUNNING_TOOLS);

		// populate the toolbar if the workspace has running tools
		if (ws != null) {
			PluginTool[] tools = ws.getTools();
			for (PluginTool element : tools) {
				addTool(element);
			}
		}

		validate();
	}

	@Override
	public Dimension getPreferredSize() {
		return runningToolbar.getPreferredSize();
	}

	void addTool(PluginTool runningTool) {
		ToolButton toolButton =
			new ToolButton(plugin, runningTool, runningTool.getToolTemplate(true));
		runningToolbar.add(toolButton);
		runningTools.put(runningTool, toolButton);
		runningToolbar.invalidate();
		validate();
		repaint();
	}

	void removeTool(PluginTool tool) {
		ToolButton button = runningTools.get(tool);
		if (button == null) {
			return;
		}
		runningToolbar.remove(button);
		runningTools.remove(tool);
		runningToolbar.invalidate();
		button.dispose();
		validate();
		repaint();
	}

	// parameter not used
	void toolNameChanged(PluginTool changedTool) {
	}

	/**
	 * Update the tool template for the tool button.
	 */
	void updateToolButton(PluginTool tool, ToolTemplate template, Icon icon) {
		ToolButton button = runningTools.get(tool);

		if (button != null) {
			button.setToolTemplate(template, icon);
		}
		validate();
		repaint();
	}
}
