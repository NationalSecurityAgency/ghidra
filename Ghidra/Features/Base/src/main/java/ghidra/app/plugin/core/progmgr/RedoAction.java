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
package ghidra.app.plugin.core.progmgr;

import java.io.IOException;

import javax.swing.Icon;

import docking.action.*;
import docking.tool.ToolConstants;
import ghidra.app.services.GoToService;
import ghidra.app.services.NavigationHistoryService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import resources.ResourceManager;

/**
 * Action class for the "redo" action
 */
public class RedoAction extends AbstractProgramNameSwitchingAction {
	private final PluginTool tool;

	public RedoAction(ProgramManagerPlugin plugin, PluginTool tool) {
		super(plugin, "Redo", true);
		this.tool = tool;
		setHelpLocation(new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Redo"));
		String[] menuPath = { ToolConstants.MENU_EDIT, "&Redo" };
		String group = "Undo";
		Icon icon = ResourceManager.loadImage("images/redo.png");
		MenuData menuData = new MenuData(menuPath, icon, group);
		menuData.setMenuSubGroup("2Redo"); // make this appear below the undo menu item
		setMenuBarData(menuData);
		setToolBarData(new ToolBarData(icon, group));
		setKeyBindingData(new KeyBindingData("ctrl shift Z"));
		setDescription("Redo");
	}

	@Override
	protected void actionPerformed(Program program) {
		try {
			saveCurrentLocationToHistory();
			program.redo();
		}
		catch (IOException e) {
			Msg.showError(this, null, null, null, e);
		}
	}

	void updateActionMenuName() {
		updateActionMenuName(lastContextProgram);
	}

	void updateActionMenuName(Program program) {
		String actionName = "Redo " + (program == null ? "" : program.getDomainFile().getName());
		String description = actionName;

		if (program != null && program.canRedo()) {
			description = HTMLUtilities
					.toWrappedHTML("Redo " + HTMLUtilities.escapeHTML(program.getRedoName()));
		}

		getMenuBarData().setMenuItemName(actionName);
		setDescription(description);
	}

	protected void programChanged(Program program) {
		updateActionMenuName(program);
	}

	@Override
	protected boolean isEnabledForContext(Program program) {
		return program != null && program.canRedo();
	}

	private void saveCurrentLocationToHistory() {
		GoToService goToService = tool.getService(GoToService.class);
		NavigationHistoryService historyService = tool.getService(NavigationHistoryService.class);
		if (goToService != null && historyService != null) {
			historyService.addNewLocation(goToService.getDefaultNavigatable());
		}
	}
}
