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
package ghidra.app.plugin.core.decompile.actions;

import docking.ActionContext;
import docking.action.MenuData;
import ghidra.app.actions.AbstractFindReferencesDataTypeAction;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.*;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesService;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.util.HelpLocation;

public class FindReferencesToDataTypeAction extends AbstractFindReferencesDataTypeAction {

	private final DecompilerController controller;

	public FindReferencesToDataTypeAction(String owner, PluginTool tool,
			DecompilerController controller) {
		super(tool, NAME, owner, DEFAULT_KEY_STROKE);
		this.controller = controller;

		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionFindUses"));
		setPopupMenuData(
			new MenuData(new String[] { LocationReferencesService.MENU_GROUP, "Find Uses of " }));
	}

	@Override
	public DataType getDataType(ActionContext context) {
		return DecompilerUtils.getDataType((DecompilerActionContext) context);
	}

	@Override
	protected String getDataTypeField(DataType dataType) {

		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		if (tokenAtCursor instanceof ClangFieldToken) {
			return tokenAtCursor.getText();
		}

		if (tokenAtCursor instanceof ClangVariableToken) {

			if (dataType instanceof Enum) {

				// check for enum field
				ClangVariableToken vt = (ClangVariableToken) tokenAtCursor;
				String text = vt.getText();
				Enum e = (Enum) dataType;
				String[] names = e.getNames();
				for (String name : names) {
					if (name.equals(text)) {
						return name;
					}
				}
			}
		}

		return null;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DecompilerActionContext)) {
			return false;
		}

		DataType dataType = getDataType(context);
		updateMenuName(dataType);
		return super.isEnabledForContext(context);
	}

	private void updateMenuName(DataType type) {

		if (type == null) {
			return; // not sure if this can happen
		}

		String typeName = type.getName();
		String menuName = "Find Uses of " + typeName;
		String fieldName = getDataTypeField(type);
		if (fieldName != null) {
			menuName += '.' + fieldName;
		}

		MenuData data = getPopupMenuData().cloneData();
		data.setMenuPath(new String[] { LocationReferencesService.MENU_GROUP, menuName });
		setPopupMenuData(data);
	}
}
