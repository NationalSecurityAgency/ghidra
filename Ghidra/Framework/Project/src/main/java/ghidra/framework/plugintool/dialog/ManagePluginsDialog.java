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
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.*;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.main.AppInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.classfinder.ClassSearcher;
import resources.ResourceManager;

public class ManagePluginsDialog extends DialogComponentProvider implements ChangeListener {

	private PluginTool tool;
	private boolean isNewTool;
	private DockingAction saveAction;
	private DockingAction saveAsAction;
	private DockingAction configureAllPluginsAction;
	private PluginManagerComponent comp;

	public ManagePluginsDialog(PluginTool tool, boolean addSaveActions, boolean isNewTool) {
		super("Configure Tool", false, true, true, true);
		this.tool = tool;
		this.isNewTool = isNewTool;
		ClassSearcher.addChangeListener(this);
		comp = new PluginManagerComponent(tool);
		JScrollPane scrollPane = new JScrollPane(comp);
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
		ClassSearcher.removeChangeListener(this);
		close();
	}

	private void createActions(boolean addSaveActions) {
		configureAllPluginsAction =
			new DockingAction("Configure All Plugins", ToolConstants.TOOL_OWNER) {
				@Override
				public void actionPerformed(ActionContext context) {
					comp.manageAllPlugins();
				}
			};
		ImageIcon icon = ResourceManager.loadImage("images/plugin.png");
		configureAllPluginsAction.setToolBarData(new ToolBarData(icon, "aaa"));
		configureAllPluginsAction.setDescription("Configure All Plugins");
		configureAllPluginsAction.setHelpLocation(
			new HelpLocation(GenericHelpTopics.TOOL, "ConfigureAllPlugins"));
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
			saveAsAction.setMenuBarData(
				new MenuData(new String[] { "Save As..." }, icon, saveGroup));
			saveAsAction.setToolBarData(new ToolBarData(icon, saveGroup));
			saveAsAction.setHelpLocation(new HelpLocation(GenericHelpTopics.TOOL, "SaveTool"));
			saveAsAction.setDescription("Save tool to new name in tool chest");
			addAction(saveAsAction);
		}
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

	@Override
	public void stateChanged(ChangeEvent e) {
		//comp.refresh();
	}

	public void stateChanged() {
		if (saveAction != null) {
			saveAction.setEnabled(tool.hasConfigChanged());
		}
	}

}
