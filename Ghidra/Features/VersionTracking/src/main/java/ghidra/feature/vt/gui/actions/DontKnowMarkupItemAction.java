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
package ghidra.feature.vt.gui.actions;

import static ghidra.feature.vt.gui.provider.markuptable.MarkupStatusIcons.DONT_KNOW_ICON;
import ghidra.feature.vt.api.main.VTMarkupItemConsideredStatus;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.util.HelpLocation;
import docking.action.MenuData;
import docking.action.ToolBarData;

public class DontKnowMarkupItemAction extends SetMarkupItemConsideredAction {

	private static final String MENU_GROUP = VTPlugin.EDIT_MENU_GROUP;

	public DontKnowMarkupItemAction(VTController controller, boolean addToToolbar) {
		super(controller, "Don't Know");

		if (addToToolbar) {
			setToolBarData(new ToolBarData(DONT_KNOW_ICON, MENU_GROUP));
		}
		MenuData menuData = new MenuData(new String[] { "Don't Know" }, DONT_KNOW_ICON, MENU_GROUP);
		setPopupMenuData(menuData);
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Tag_Markup_Item_Dont_Know"));
	}

	@Override
	VTMarkupItemConsideredStatus getTagType() {
		return VTMarkupItemConsideredStatus.IGNORE_DONT_KNOW;
	}
}
