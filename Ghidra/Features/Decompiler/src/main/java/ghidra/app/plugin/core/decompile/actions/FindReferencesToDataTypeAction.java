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
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;

public class FindReferencesToDataTypeAction extends AbstractFindReferencesDataTypeAction {

	private final DecompilerController controller;

	public FindReferencesToDataTypeAction(String owner, PluginTool tool,
			DecompilerController controller) {
		super(tool, NAME, owner, DEFAULT_KEY_STROKE);
		this.controller = controller;

		setPopupMenuData(
			new MenuData(new String[] { LocationReferencesService.MENU_GROUP, "Find Uses of " }));
	}

	@Override
	public DataType getDataType(ActionContext context) {

		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();

		// prefer the selection over the current location
		ClangToken token = decompilerPanel.getSelectedToken();
		if (token == null) {
			token = decompilerPanel.getTokenAtCursor();
		}

		Varnode varnode = DecompilerUtils.getVarnodeRef(token);
		if (varnode != null) {
			HighVariable highVariable = varnode.getHigh();
			if (highVariable != null) {
				DataType dataType = highVariable.getDataType();
				return dataType;

			}
		}

		if (token instanceof ClangTypeToken) {
			DataType dataType = ((ClangTypeToken) token).getDataType();
			return dataType;
		}

		if (token instanceof ClangFieldToken) {
			DataType dataType = ((ClangFieldToken) token).getDataType();
			return dataType;
		}

		return null;
	}

	@Override
	protected String getDataTypeField() {

		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		if (tokenAtCursor instanceof ClangFieldToken) {
			return tokenAtCursor.getText();
		}

		return null;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DecompilerActionContext)) {
			return false;
		}

		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			// Let this through here and handle it in actionPerformed().  This lets us alert 
			// the user that they have to wait until the decompile is finished.  If we are not
			// enabled at this point, then the keybinding will be propagated to the global 
			// actions, which is not what we want.
			return true;
		}

		DataType dataType = getDataType(context);
		updateMenuName(dataType);

		return super.isEnabledForContext(context);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// Note: we intentionally do this check here and not in isEnabledForContext() so 
		// that global events do not get triggered.
		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			Msg.showInfo(getClass(), context.getComponentProvider().getComponent(),
				"Decompiler Action Blocked",
				"You cannot perform Decompiler actions while the Decompiler is busy");
			return;
		}

		super.actionPerformed(context);
	}

	private void updateMenuName(DataType type) {

		if (type == null) {
			return; // not sure if this can happen
		}

		String typeName = type.getName();
		String menuName = "Find Uses of " + typeName;

		String fieldName = getDataTypeField();
		if (fieldName != null) {
			menuName += '.' + fieldName;
		}

		MenuData data = getPopupMenuData().cloneData();
		data.setMenuPath(new String[] { LocationReferencesService.MENU_GROUP, menuName });
		setPopupMenuData(data);
	}
}
