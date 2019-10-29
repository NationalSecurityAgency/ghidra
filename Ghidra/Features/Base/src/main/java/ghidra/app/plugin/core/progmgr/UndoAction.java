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

import java.awt.event.InputEvent;
import java.io.IOException;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.*;
import docking.tool.ToolConstants;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.context.ProgramContextAction;
import ghidra.app.services.GoToService;
import ghidra.app.services.NavigationHistoryService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import resources.ResourceManager;

public class UndoAction extends ProgramContextAction {
	private final PluginTool tool;

	public UndoAction(PluginTool tool, String owner) {
		super("Undo", owner);
		this.tool = tool;
		setHelpLocation(new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Undo"));
		String[] menuPath = { ToolConstants.MENU_EDIT, "&Undo" };
		Icon icon = ResourceManager.loadImage("images/undo.png");
		MenuData menuData = new MenuData(menuPath, icon, "Undo");
		menuData.setMenuSubGroup("1Undo"); // make this appear above the redo menu item
		setMenuBarData(menuData);
		setToolBarData(new ToolBarData(icon, "Undo"));
		setDescription("Undo");
		setKeyBindingData(new KeyBindingData('Z', InputEvent.CTRL_MASK));
	}

	@Override
	protected void actionPerformed(ProgramActionContext programContext) {
		Program program = programContext.getProgram();
		try {
			saveCurrentLocationToHistory();
			program.undo();
		}
		catch (IOException e) {
			Msg.showError(this, null, null, null, e);
		}
	}

	private void saveCurrentLocationToHistory() {
		GoToService goToService = tool.getService(GoToService.class);
		NavigationHistoryService historyService = tool.getService(NavigationHistoryService.class);
		if (goToService != null && historyService != null) {
			historyService.addNewLocation(goToService.getDefaultNavigatable());
		}
	}

	@Override
	protected boolean isEnabledForContext(ProgramActionContext context) {
		Program program = context.getProgram();
		if (program.canUndo()) {
			String programName = program.getDomainFile().getName();
			getMenuBarData().setMenuItemName("Undo " + programName);
			String tip = HTMLUtilities.toWrappedHTML(
				"Undo " + HTMLUtilities.escapeHTML(program.getUndoName()));
			setDescription(tip);
			return true;
		}
		return false;
	}

	@Override
	public boolean isEnabledForContext(ActionContext actionContext) {
		if (!super.isEnabledForContext(actionContext)) {
			setDescription("Undo");
			getMenuBarData().setMenuItemName("Undo");
			return false;
		}
		return true;
	}
}
