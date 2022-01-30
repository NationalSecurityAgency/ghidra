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
package ghidra.framework.plugintool.dialog;

import java.awt.Color;
import java.awt.Point;

import javax.swing.*;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.*;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.main.AppInfo;
import ghidra.framework.plugintool.PluginConfigurationModel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginPackage;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

public class ManagePluginsDialog extends DialogComponentProvider {

	private PluginTool tool;
	private boolean isNewTool;
	private DockingAction saveAction;
	private DockingAction saveAsAction;
	private DockingAction configureAllPluginsAction;
	private PluginManagerComponent pluginComponent;
	private PluginConfigurationModel pluginConfigurationModel;

	public ManagePluginsDialog(PluginTool tool, boolean addSaveActions, boolean isNewTool) {
		this(tool, new PluginConfigurationModel(tool), addSaveActions, isNewTool);
	}

	public ManagePluginsDialog(PluginTool tool, PluginConfigurationModel pluginConfigurationModel,
			boolean addSaveActions, boolean isNewTool) {
		super("Configure Tool", false, true, true, true);
		this.tool = tool;
		this.isNewTool = isNewTool;
		this.pluginConfigurationModel = pluginConfigurationModel;
		pluginComponent = new PluginManagerComponent(tool, pluginConfigurationModel);
		JScrollPane scrollPane = new JScrollPane(pluginComponent);
		scrollPane.getViewport().setBackground(Color.white);
		scrollPane.getViewport().setViewPosition(new Point(0, 0));
		addWorkPanel(scrollPane);
		createActions(addSaveActions);
		if (tool == AppInfo.getFrontEndTool()) {
			setHelpLocation(new HelpLocation(GenericHelpTopics.FRONT_END, "Configure"));
		}
		else {
			setHelpLocation(new HelpLocation(GenericHelpTopics.TOOL, "Configure_Tool"));
		}
		setRememberSize(false);

		JButton doneButton = new JButton("Close");
		doneButton.addActionListener(e -> close());
		addButton(doneButton);
	}

	DockingAction getSaveAction() {
		return saveAction;
	}

	DockingAction getSaveAsAction() {
		return saveAsAction;
	}

	@Override
	protected void escapeCallback() {
		if (isNewTool && tool.hasConfigChanged()) {
			String title = "New Tool Not Saved";
			String message = "New Tool has not been saved to your Tool Chest.";
			int result = OptionDialog.showOptionDialog(rootPanel, title,
				message + "\nDo you want to save it now?", "&Yes", "&No",
				OptionDialog.QUESTION_MESSAGE);
			if (result == OptionDialog.CANCEL_OPTION) {
				return;
			}
			if (result == OptionDialog.OPTION_ONE) {
				save();
			}
		}
		close();
	}

	private void createActions(boolean addSaveActions) {
		configureAllPluginsAction =
			new DockingAction("Configure All Plugins", ToolConstants.TOOL_OWNER) {
				@Override
				public void actionPerformed(ActionContext context) {
					pluginComponent.manageAllPlugins();
				}
			};
		ImageIcon icon = ResourceManager.loadImage("images/plugin.png");
		configureAllPluginsAction.setToolBarData(new ToolBarData(icon, "aaa"));
		configureAllPluginsAction.setDescription("Configure All Plugins");
		configureAllPluginsAction
				.setHelpLocation(new HelpLocation(GenericHelpTopics.TOOL, "ConfigureAllPlugins"));
		addAction(configureAllPluginsAction);

		if (addSaveActions) {
			saveAction = new DockingAction("Save New Tool", ToolConstants.TOOL_OWNER) {
				@Override
				public void actionPerformed(ActionContext context) {
					save();
				}
			};
			saveAction.setEnabled(tool.hasConfigChanged());
			icon = ResourceManager.loadImage("images/disk.png");
			String saveGroup = "save";
			saveAction.setMenuBarData(new MenuData(new String[] { "Save" }, icon, saveGroup));
			saveAction.setToolBarData(new ToolBarData(icon, saveGroup));
			saveAction.setHelpLocation(new HelpLocation(GenericHelpTopics.TOOL, "SaveTool"));
			saveAction.setDescription("Save tool to tool chest");
			addAction(saveAction);

			saveAsAction = new DockingAction("Save New Tool As", ToolConstants.TOOL_OWNER) {
				@Override
				public void actionPerformed(ActionContext context) {
					saveAs();
				}
			};
			saveAsAction.setEnabled(true);
			icon = ResourceManager.loadImage("images/disk_save_as.png");
			saveAsAction
					.setMenuBarData(new MenuData(new String[] { "Save As..." }, icon, saveGroup));
			saveAsAction.setToolBarData(new ToolBarData(icon, saveGroup));
			saveAsAction.setHelpLocation(new HelpLocation(GenericHelpTopics.TOOL, "SaveTool"));
			saveAsAction.setDescription("Save tool to new name in tool chest");
			addAction(saveAsAction);
		}
	}

	public PluginConfigurationModel getPluginConfigurationModel() {
		return pluginConfigurationModel;
	}

	private void save() {
		if (isNewTool) {
			saveAs();
		}
		else {
			tool.getToolServices().saveTool(tool);
			saveAction.setEnabled(false);
		}
	}

	private void saveAs() {
		tool.saveToolAs();
		saveAction.setEnabled(tool.hasConfigChanged());
		isNewTool = false;
	}

	public void stateChanged() {
		if (saveAction != null) {
			saveAction.setEnabled(tool.hasConfigChanged());
		}
	}

	int getPackageCount() {
		return pluginComponent.getPackageCount();
	}

	int getPluginCount(PluginPackage pluginPackage) {
		return pluginComponent.getPluginCount(pluginPackage);
	}

	PluginManagerComponent getPluginComponent() {
		return pluginComponent;
	}
}
