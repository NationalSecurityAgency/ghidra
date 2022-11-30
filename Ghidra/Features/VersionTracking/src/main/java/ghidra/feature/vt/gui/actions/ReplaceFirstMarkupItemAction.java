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
package ghidra.feature.vt.gui.actions;

import static ghidra.feature.vt.gui.util.VTOptionDefines.*;

import javax.swing.Icon;

import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.feature.vt.api.main.VTMarkupItemApplyActionType;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.ReplaceDataChoices;
import ghidra.framework.options.ToolOptions;
import ghidra.util.HelpLocation;

/**
 * Action that replaces Data for a version tracking data match, but only if no defined data 
 * in the destination is replaced other than defined data at the match's destination address. 
 * If the source data type would overwrite other defined data whose address is beyond the 
 * destination address, then no replace will occur.
 */
public class ReplaceFirstMarkupItemAction extends AbstractMarkupItemAction {

	private static final String MENU_GROUP = VTPlugin.APPLY_EDIT_MENU_GROUP;

	/**
	 * Constructor for action to only replace the first item (i.e. defined data at the 
	 * destination address, but don't replace if other defined data beyond the destination 
	 * address would be overwritten.)
	 * @param controller the version tracking session controller
	 * @param addToToolbar true indicates this action's icon should be added to the 
	 * window provider's toolbar.
	 */
	public ReplaceFirstMarkupItemAction(VTController controller, boolean addToToolbar) {
		super(controller, "Apply (Replace First Only)");

		Icon replacedIcon = VTPlugin.REPLACED_ICON;

		if (addToToolbar) {
			setToolBarData(new ToolBarData(replacedIcon, MENU_GROUP));
		}
		MenuData menuData =
			new MenuData(new String[] { "Apply (Replace First Only)" }, replacedIcon, MENU_GROUP);
		menuData.setMenuSubGroup("2");
		setPopupMenuData(menuData);
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Replace_First_Markup_Item"));
	}

	@Override
	public ToolOptions getApplyOptions() {
		ToolOptions options = controller.getOptions();
		ToolOptions vtOptions = options.copy();
		vtOptions.setEnum(DATA_MATCH_DATA_TYPE, ReplaceDataChoices.REPLACE_FIRST_DATA_ONLY);

		return vtOptions;
	}

	@Override
	public VTMarkupItemApplyActionType getActionType() {
		return VTMarkupItemApplyActionType.REPLACE_FIRST_ONLY;
	}
}
