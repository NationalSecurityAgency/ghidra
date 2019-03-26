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
import javax.swing.ImageIcon;

import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.feature.vt.api.main.VTMarkupItemApplyActionType;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.*;
import ghidra.framework.options.ToolOptions;
import ghidra.util.HelpLocation;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.TranslateIcon;

public class ReplaceDefaultMarkupItemAction extends AbstractMarkupItemAction {

	private static final String MENU_GROUP = VTPlugin.APPLY_EDIT_MENU_GROUP;

	public ReplaceDefaultMarkupItemAction(VTController controller, boolean addToToolbar) {
		super(controller, "Apply (Replace Default Only)");

		Icon replacedIcon = VTPlugin.REPLACED_ICON;
		ImageIcon warningIcon = ResourceManager.loadImage("images/warning.png");
		warningIcon = ResourceManager.getScaledIcon(warningIcon, 12, 12);
		int warningIconWidth = warningIcon.getIconWidth();
		int warningIconHeight = warningIcon.getIconHeight();

		MultiIcon multiIcon = new MultiIcon(replacedIcon);
		int refreshIconWidth = replacedIcon.getIconWidth();
		int refreshIconHeight = replacedIcon.getIconHeight();

		int x = refreshIconWidth - warningIconWidth;
		int y = refreshIconHeight - warningIconHeight;

		TranslateIcon translateIcon = new TranslateIcon(warningIcon, x, y);
		multiIcon.addIcon(translateIcon);

		if (addToToolbar) {
			setToolBarData(new ToolBarData(multiIcon, MENU_GROUP));
		}
		MenuData menuData =
			new MenuData(new String[] { "Apply (Replace Default Only)" }, replacedIcon, MENU_GROUP);
		menuData.setMenuSubGroup("2");
		setPopupMenuData(menuData);
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Replace_Default_Markup_Item"));
	}

	@Override
	public ToolOptions getApplyOptions() {
		ToolOptions options = controller.getOptions();
		ToolOptions vtOptions = options.copy();
		vtOptions.setEnum(FUNCTION_NAME, FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		vtOptions.setEnum(LABELS, LabelChoices.REPLACE_DEFAULT_ONLY);
		vtOptions.setEnum(FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		vtOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		vtOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE_DEFAULTS_ONLY);
		vtOptions.setEnum(DATA_MATCH_DATA_TYPE, SourcePriorityChoices.REPLACE_DEFAULTS_ONLY);

		return vtOptions;
	}

	@Override
	public VTMarkupItemApplyActionType getActionType() {
		return VTMarkupItemApplyActionType.REPLACE_DEFAULT_ONLY;
	}
}
