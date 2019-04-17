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

import java.util.*;

import javax.swing.BorderFactory;
import javax.swing.JToolBar;

import ghidra.framework.model.*;

/**
 * Toolbar that shows icons for the tools in the user's tool chest.
 */
class ProjectToolBar extends JToolBar implements ToolChestChangeListener {
	private final static int TYPICAL_NUM_TOOLS = 5;

	private Map<String, ToolButton> toolButtonMap;
	private FrontEndPlugin plugin;
	private FrontEndTool tool;

	ProjectToolBar(FrontEndPlugin plugin) {
		super();
		this.plugin = plugin;
		tool = ((FrontEndTool) plugin.getTool());
		toolButtonMap = new HashMap<>(TYPICAL_NUM_TOOLS);

		// remove the default etched border
		setBorder(BorderFactory.createTitledBorder("Tool Chest"));

		setActiveProject(plugin.getActiveProject());

		// let the default coloring shine through this toolbar; leaving this opaque causes
		// odd display coloring issues in some LookAndFeels, like Metal
		setOpaque(false);
		setFloatable(false); // it is odd to allow the user to undock the tool buttons
	}

	@Override
	public void toolTemplateAdded(ToolTemplate toolConfig) {
		// rebuild the tool bar so that the tools are shown in
		// alphabetical order
		populateToolBar();
	}

	/**
	 * ToolSet was added to the project toolchest
	 */
	@Override
	public void toolSetAdded(ToolSet toolset) {
		ToolChest toolChest = tool.getProject().getLocalToolChest();
		toolTemplateAdded(toolChest.getToolTemplate(toolset.getName()));
	}

	@Override
	public void toolRemoved(String toolName) {
		if (!toolButtonMap.containsKey(toolName)) {
			return;
		}
		ToolButton button = toolButtonMap.get(toolName);
		this.remove(button);
		toolButtonMap.remove(toolName);
		button.dispose();

		tool.getToolFrame().validate();

		repaint();
	}

	void setActiveProject(Project project) {
		// first clear state from previous project
		clear();

		if (project == null) {
			return;
		}
		populateToolBar();
	}

	private void clear() {
		this.removeAll();
		Iterator<ToolButton> it = toolButtonMap.values().iterator();
		while (it.hasNext()) {
			ToolButton tb = it.next();
			tb.dispose();
		}
		toolButtonMap.clear();

		if (tool.isVisible()) {
			tool.getToolFrame().validate();
		}
	}

	/**
	 * Redo the tool bar.
	 */
	private void populateToolBar() {
		removeAll();
		toolButtonMap.clear();
		ToolChest tc = plugin.getActiveProject().getLocalToolChest();
		ToolTemplate[] templates = tc.getToolTemplates();
		for (ToolTemplate element : templates) {
			addConfig(element);
		}
		invalidate();
		tool.getToolFrame().validate();
		repaint();
	}

	/**
	 * Add a button for the tool template to the tool bar.
	 */
	private void addConfig(ToolTemplate toolConfig) {
		ToolButton button = new ToolButton(plugin, toolConfig);
		this.add(button);
		toolButtonMap.put(toolConfig.getName(), button);
	}

	public ToolButton getToolButtonForToolConfig(ToolTemplate toolTemplate) {
		return toolButtonMap.get(toolTemplate.getName());
	}
}
