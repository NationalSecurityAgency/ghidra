/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.nav.NextRangeAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.ToolConstants;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import resources.ResourceManager;
import docking.action.*;

public class NextHighlightedRangeAction extends NextRangeAction {

	public NextHighlightedRangeAction(PluginTool tool, String owner, NavigationOptions navOptions) {
		super(tool, "Next Highlighted Range", owner, navOptions);
		setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_NAVIGATION,
			"Next Highlight Range" }, ResourceManager.loadImage("images/NextHighlightBlock16.gif"),
			PluginCategoryNames.NAVIGATION, MenuData.NO_MNEMONIC,
			NextPrevHighlightRangePlugin.ACTION_SUB_GROUP));

		setToolBarData(new ToolBarData(
			ResourceManager.loadImage("images/NextHighlightBlock16.gif"),
			PluginCategoryNames.NAVIGATION, NextPrevHighlightRangePlugin.ACTION_SUB_GROUP));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_0, InputEvent.CTRL_DOWN_MASK));

		setDescription("Go to next highlighted range");
		setHelpLocation(new HelpLocation(HelpTopics.HIGHLIGHT, getName()));

	}

	@Override
	protected ProgramSelection getSelection(ProgramLocationActionContext context) {
		return context.getHighlight();
	}

}
