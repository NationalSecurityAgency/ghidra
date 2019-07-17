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

import static ghidra.feature.vt.api.main.VTMarkupItemApplyActionType.REPLACE;
import static ghidra.feature.vt.gui.provider.markuptable.MarkupStatusIcons.APPLY_REPLACE_MENU_ICON;
import static ghidra.feature.vt.gui.util.VTOptionDefines.*;

import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.feature.vt.api.main.VTMarkupItemApplyActionType;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.*;
import ghidra.framework.options.ToolOptions;
import ghidra.util.HelpLocation;

public class ApplyAndReplaceMarkupItemAction extends AbstractMarkupItemAction {

	private static final String MENU_GROUP = VTPlugin.APPLY_EDIT_MENU_GROUP;

	public ApplyAndReplaceMarkupItemAction(VTController controller, boolean addToToolbar) {
		super(controller, "Apply (Replace)");

		if (addToToolbar) {
			setToolBarData(new ToolBarData(APPLY_REPLACE_MENU_ICON, MENU_GROUP));
		}
		MenuData menuData =
			new MenuData(new String[] { "Apply (Replace)" }, APPLY_REPLACE_MENU_ICON, MENU_GROUP);
		menuData.setMenuSubGroup("2");
		setPopupMenuData(menuData);
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Replace_Markup_Item"));
	}

	@Override
	public ToolOptions getApplyOptions() {
		ToolOptions options = controller.getOptions();
		ToolOptions vtOptions = options.copy();

		vtOptions.setEnum(DATA_MATCH_DATA_TYPE, ReplaceDataChoices.REPLACE_ALL_DATA);

		LabelChoices labelChoice = vtOptions.getEnum(LABELS, LabelChoices.REPLACE_ALL);
		if (labelChoice != LabelChoices.REPLACE_DEFAULT_ONLY) {
			vtOptions.setEnum(LABELS, LabelChoices.REPLACE_ALL);
		}

		FunctionNameChoices functionNameChoice =
			vtOptions.getEnum(FUNCTION_NAME, FunctionNameChoices.REPLACE_ALWAYS);
		if (functionNameChoice != FunctionNameChoices.REPLACE_DEFAULT_ONLY) {
			vtOptions.setEnum(FUNCTION_NAME, FunctionNameChoices.REPLACE_ALWAYS);
		}

		vtOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		vtOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.NAME_MATCH);
		vtOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		vtOptions.setEnum(NO_RETURN, ReplaceChoices.REPLACE);
		vtOptions.setEnum(VAR_ARGS, ReplaceChoices.REPLACE);
		vtOptions.setEnum(CALL_FIXUP, ReplaceChoices.REPLACE);
		vtOptions.setEnum(FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		vtOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		vtOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		// Since this is simply doing a replace, it doesn't need to set parameter name's
		// highest priority or replace if same source flag.
		vtOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.OVERWRITE_EXISTING);

		vtOptions.setEnum(PLATE_COMMENT, CommentChoices.OVERWRITE_EXISTING);
		vtOptions.setEnum(PRE_COMMENT, CommentChoices.OVERWRITE_EXISTING);
		vtOptions.setEnum(END_OF_LINE_COMMENT, CommentChoices.OVERWRITE_EXISTING);
		vtOptions.setEnum(REPEATABLE_COMMENT, CommentChoices.OVERWRITE_EXISTING);
		vtOptions.setEnum(POST_COMMENT, CommentChoices.OVERWRITE_EXISTING);

		return vtOptions;
	}

	@Override
	public VTMarkupItemApplyActionType getActionType() {
		return REPLACE;
	}
}
