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
package ghidra.framework.plugintool;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import docking.ActionContext;
import docking.action.*;
import docking.tool.ToolConstants;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.framework.plugintool.util.PluginClassManager;
import ghidra.util.HelpLocation;

public class StandAlonePluginTool extends PluginTool {

	private PluginClassManager pluginClassManager;
	private DockingAction configureToolAction;
	private final GenericStandAloneApplication app;
	private final String name;

	public StandAlonePluginTool(GenericStandAloneApplication app, String name, boolean hasStatus) {
		super(null, null, app.getToolServices(), name, true, hasStatus, false);
		this.app = app;
		this.name = name;
	}

	@Override
	public PluginClassManager getPluginClassManager() {
		if (pluginClassManager == null) {
			pluginClassManager = new PluginClassManager(Plugin.class, null);
		}
		return pluginClassManager;
	}

	@Override
	public void addExitAction() {
		DockingAction exitAction = new DockingAction("Exit", ToolConstants.TOOL_OWNER) {
			@Override
			public void actionPerformed(ActionContext context) {
				app.exit();
			}
		};
		exitAction.setHelpLocation(
			new HelpLocation(ToolConstants.FRONT_END_HELP_TOPIC, exitAction.getName()));
		exitAction.setMenuBarData(new MenuData(
			new String[] { ToolConstants.MENU_FILE, "E&xit " + name }, null, "Window_Z"));

		if (Platform.CURRENT_PLATFORM.getOperatingSystem() != OperatingSystem.MAC_OS_X) {
			// Mac Handles this action 'special'
			exitAction.setKeyBindingData(
				new KeyBindingData(KeyEvent.VK_Q, InputEvent.CTRL_DOWN_MASK));
		}

		exitAction.setEnabled(true);
		addAction(exitAction);
	}

	@Override
	public void addExportToolAction() {
		super.addExportToolAction();
	}

	@Override
	public void addSaveToolAction() {
		super.addSaveToolAction();
	}

	public void addManagePluginsAction() {

		configureToolAction = new DockingAction("Configure Tool", ToolConstants.TOOL_OWNER) {
			@Override
			public void actionPerformed(ActionContext context) {
				showConfig(false, false);
			}
		};

		configureToolAction.setMenuBarData(new MenuData(
			new String[] { ToolConstants.MENU_FILE, "Configure..." }, null, "PrintPost_PreTool"));

		configureToolAction.setEnabled(true);
		addAction(configureToolAction);
	}
}
