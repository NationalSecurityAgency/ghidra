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
import ghidra.util.HTMLUtilities;

/**
 * Action class for the "Save As" action
 */
public class SaveAsProgramAction extends AbstractProgramNameSwitchingAction {

	public SaveAsProgramAction(ProgramManagerPlugin plugin, String group, int subGroup) {
		super(plugin, "Save As File");
		MenuData menuData = new MenuData(new String[] { ToolConstants.MENU_FILE, "S&ave As..." });
		menuData.setMenuGroup(group);
		menuData.setMenuSubGroup(Integer.toString(subGroup));
		setMenuBarData(menuData);
	}

	@Override
	protected void programChanged(Program program) {
		if (program == null) {
			getMenuBarData().setMenuItemName("S&ave As...");
		}
		else {
			String progName = program.getDomainFile().getName();
			getMenuBarData().setMenuItemNamePlain("Save '%s' As...".formatted(progName));
			getMenuBarData().setMnemonic('a');
			setDescription("<html>Save '%s' As".formatted(HTMLUtilities.escapeHTML(progName)));
		}
	}

	@Override
	public void actionPerformed(Program program) {
		plugin.saveProgramAs(program);
	}

}
