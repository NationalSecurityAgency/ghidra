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

import static ghidra.feature.vt.gui.provider.markuptable.MarkupStatusIcons.APPLY_ADD_MENU_ICON;
import static ghidra.feature.vt.gui.util.VTOptionDefines.FUNCTION_NAME;

import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.feature.vt.api.main.VTMarkupItemApplyActionType;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.FunctionNameChoices;
import ghidra.framework.options.ToolOptions;
import ghidra.util.HelpLocation;

public class ApplyAndAddAsPrimaryMarkupItemAction extends AbstractMarkupItemAction {

	private static final String MENU_GROUP = VTPlugin.APPLY_EDIT_MENU_GROUP;

	public ApplyAndAddAsPrimaryMarkupItemAction(VTController controller, boolean addToToolbar) {
		super(controller, "Apply (Add As Primary)");

		if (addToToolbar) {
			setToolBarData(new ToolBarData(APPLY_ADD_MENU_ICON, MENU_GROUP));
		}
		MenuData menuData = new MenuData(new String[] { "Apply (Add As Primary)" },
			APPLY_ADD_MENU_ICON, MENU_GROUP);
		menuData.setMenuSubGroup("1");
		setPopupMenuData(menuData);
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Add_As_Primary_Markup_Item"));
	}

	@Override
	public ToolOptions getApplyOptions() {
		ToolOptions options = controller.getOptions();
		ToolOptions vtOptions = options.copy();
		vtOptions.setEnum(FUNCTION_NAME, FunctionNameChoices.ADD_AS_PRIMARY);

		return vtOptions;
	}

	@Override
	public VTMarkupItemApplyActionType getActionType() {
		return VTMarkupItemApplyActionType.ADD_AS_PRIMARY;
	}
}
