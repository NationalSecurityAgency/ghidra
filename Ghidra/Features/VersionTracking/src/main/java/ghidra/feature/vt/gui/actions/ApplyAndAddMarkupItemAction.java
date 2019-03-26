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

import static ghidra.feature.vt.api.main.VTMarkupItemApplyActionType.ADD;
import static ghidra.feature.vt.gui.provider.markuptable.MarkupStatusIcons.APPLY_ADD_MENU_ICON;
import static ghidra.feature.vt.gui.util.VTOptionDefines.*;
import ghidra.feature.vt.api.main.VTMarkupItemApplyActionType;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.CommentChoices;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.FunctionNameChoices;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.LabelChoices;
import ghidra.framework.options.ToolOptions;
import ghidra.util.HelpLocation;
import docking.action.MenuData;
import docking.action.ToolBarData;

public class ApplyAndAddMarkupItemAction extends AbstractMarkupItemAction {

	private static final String MENU_GROUP = VTPlugin.APPLY_EDIT_MENU_GROUP;

	public ApplyAndAddMarkupItemAction(VTController controller, boolean addToToolbar) {
		super(controller, "Apply (Add)");

		if (addToToolbar) {
			setToolBarData(new ToolBarData(APPLY_ADD_MENU_ICON, MENU_GROUP));
		}
		MenuData menuData =
			new MenuData(new String[] { "Apply (Add)" }, APPLY_ADD_MENU_ICON, MENU_GROUP);
		menuData.setMenuSubGroup("1");
		setPopupMenuData(menuData);
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Add_Markup_Item"));
	}

	@Override
	public ToolOptions getApplyOptions() {
		ToolOptions options = controller.getOptions();
		ToolOptions vtOptions = options.copy();
		vtOptions.setEnum(FUNCTION_NAME, FunctionNameChoices.ADD);
		vtOptions.setEnum(LABELS, LabelChoices.ADD);
		vtOptions.setEnum(PLATE_COMMENT, CommentChoices.APPEND_TO_EXISTING);
		vtOptions.setEnum(PRE_COMMENT, CommentChoices.APPEND_TO_EXISTING);
		vtOptions.setEnum(END_OF_LINE_COMMENT, CommentChoices.APPEND_TO_EXISTING);
		vtOptions.setEnum(REPEATABLE_COMMENT, CommentChoices.APPEND_TO_EXISTING);
		vtOptions.setEnum(POST_COMMENT, CommentChoices.APPEND_TO_EXISTING);

		return vtOptions;
	}

	@Override
	public VTMarkupItemApplyActionType getActionType() {
		return ADD;
	}
}
