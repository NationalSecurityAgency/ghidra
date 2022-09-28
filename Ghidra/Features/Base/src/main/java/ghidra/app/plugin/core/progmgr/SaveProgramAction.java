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

import javax.swing.Icon;

import docking.action.*;
import docking.tool.ToolConstants;
import ghidra.program.model.listing.Program;
import resources.Icons;

/**
 * Action class for the "Save Program" action
 */
public class SaveProgramAction extends AbstractProgramNameSwitchingAction {

	public SaveProgramAction(ProgramManagerPlugin plugin, String group, int subGroup) {
		super(plugin, "Save File");
		MenuData menuData = new MenuData(new String[] { ToolConstants.MENU_FILE, "Save File" });
		menuData.setMenuGroup(group);
		menuData.setMenuSubGroup(Integer.toString(subGroup));
		setMenuBarData(menuData);
		Icon icon = Icons.SAVE_ICON;
		setToolBarData(new ToolBarData(icon, ToolConstants.TOOLBAR_GROUP_ONE));
		setKeyBindingData(new KeyBindingData("ctrl S"));
	}

	@Override
	protected void programChanged(Program program) {
		if (program == null) {
			getMenuBarData().setMenuItemName("&Save");
			setDescription("Save Program");
		}
		else {
			String programName = "'" + program.getDomainFile().getName() + "'";
			getMenuBarData().setMenuItemName("&Save " + programName);
			setDescription("Save " + programName);
		}
	}

	@Override
	public boolean isEnabledForContext(Program program) {
		return program != null && program.isChanged();
	}

	@Override
	public void actionPerformed(Program program) {
		plugin.saveProgram(program);
	}

}
