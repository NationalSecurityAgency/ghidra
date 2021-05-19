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
import ghidra.app.context.ProgramActionContext;
import ghidra.app.context.ProgramContextAction;
import ghidra.app.services.GoToService;
import ghidra.app.services.NavigationHistoryService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import resources.ResourceManager;

public class RedoAction extends ProgramContextAction {
	private final PluginTool tool;

	public RedoAction(PluginTool tool, String owner) {
		super("Redo", owner);
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
		setSupportsDefaultToolContext(true);

		// we want this action to appear in all windows that can produce a program context
		addToWindowWhen(ProgramActionContext.class);
	}

	@Override
	protected void actionPerformed(ProgramActionContext programContext) {
		Program program = programContext.getProgram();
		try {
			saveCurrentLocationToHistory();
			program.redo();
		}
		catch (IOException e) {
			Msg.showError(this, null, null, null, e);
		}
	}

	/**
	 * updates the menu name of the action as the undo stack changes
	 * <P>
	 * NOTE: currently, we must manage the enablement explicitly
	 * because contextChanged is not called for data changes. Ideally, the enablement
	 * would be handled by the context, but for now it doesn't work
	 *
	 * @param program the program
	 */
	public void update(Program program) {

		if (program == null) {
			getMenuBarData().setMenuItemName("Redo ");
			setDescription("");
			setEnabled(false);
		}
		else if (program.canRedo()) {
			String programName = program.getDomainFile().getName();
			getMenuBarData().setMenuItemName("Redo " + programName);
			String tip = HTMLUtilities.toWrappedHTML(
				"Redo " + HTMLUtilities.escapeHTML(program.getRedoName()));
			setDescription(tip);
			setEnabled(true);
		}
		else {
			setDescription("Redo");
			setEnabled(false);
		}

	}

	@Override
	protected boolean isEnabledForContext(ProgramActionContext context) {
		Program program = context.getProgram();
		return program.canRedo();
	}

	private void saveCurrentLocationToHistory() {
		GoToService goToService = tool.getService(GoToService.class);
		NavigationHistoryService historyService = tool.getService(NavigationHistoryService.class);
		if (goToService != null && historyService != null) {
			historyService.addNewLocation(goToService.getDefaultNavigatable());
		}
	}

}
