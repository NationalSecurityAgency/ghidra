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
package ghidra.app.plugin.core.navigation;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.ImageIcon;

import docking.DockingUtils;
import docking.action.*;
import docking.tool.ToolConstants;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.nav.PreviousRangeAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

public class PreviousSelectedRangeAction extends PreviousRangeAction {

	public PreviousSelectedRangeAction(PluginTool tool, String ownerName,
			NavigationOptions navOptions) {
		super(tool, "Previous Selected Range", ownerName, navOptions);

		ImageIcon icon = ResourceManager.loadImage("images/PreviousSelectionBlock16.gif");
		setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_NAVIGATION,
			"Previous Selected Range" }, icon, PluginCategoryNames.NAVIGATION,
			MenuData.NO_MNEMONIC, NextPrevSelectedRangePlugin.ACTION_SUB_GROUP));

		setToolBarData(new ToolBarData(icon, ToolConstants.TOOLBAR_GROUP_THREE,
			NextPrevSelectedRangePlugin.ACTION_SUB_GROUP));
		setKeyBindingData(
			new KeyBindingData(KeyEvent.VK_CLOSE_BRACKET, DockingUtils.CONTROL_KEY_MODIFIER_MASK |
				InputEvent.SHIFT_DOWN_MASK));

		setDescription("Go to previous selected range");
		setHelpLocation(new HelpLocation(HelpTopics.SELECTION, getName()));
	}

	@Override
	protected ProgramSelection getSelection(ProgramLocationActionContext context) {
		return context.getSelection();
	}
}
