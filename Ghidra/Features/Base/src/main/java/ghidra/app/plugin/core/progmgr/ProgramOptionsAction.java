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

import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.program.model.listing.Program;

/**
 * Action class for the "Edit Program Options" action
 */
public class ProgramOptionsAction extends AbstractProgramNameSwitchingAction {

	public ProgramOptionsAction(ProgramManagerPlugin plugin) {
		super(plugin, "Program Options");
		MenuData menuData =
			new MenuData(new String[] { ToolConstants.MENU_EDIT, "P&rogram Options..." });
		menuData.setMenuGroup(ToolConstants.TOOL_OPTIONS_MENU_GROUP);
		menuData.setMenuSubGroup(ToolConstants.TOOL_OPTIONS_MENU_GROUP + "b");
		setMenuBarData(menuData);
	}

	@Override
	protected void programChanged(Program program) {
		if (program == null) {
			getMenuBarData().setMenuItemName("Program Options");
		}
		else {
			String programName = "'" + program.getDomainFile().getName() + "'";
			getMenuBarData().setMenuItemName("Options for " + programName + "...");
		}
	}

	@Override
	public void actionPerformed(Program program) {
		plugin.showProgramOptions(program);
	}

}
