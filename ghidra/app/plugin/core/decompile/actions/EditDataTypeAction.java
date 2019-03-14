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

import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighVariable;
import ghidra.util.Msg;
import ghidra.util.UndefinedFunction;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

public class EditDataTypeAction extends DockingAction {
	private final DecompilerController controller;
	private final PluginTool tool;

	public EditDataTypeAction(String owner, PluginTool tool, DecompilerController controller) {
		super("EditDataType", owner);
		this.tool = tool;
		this.controller = controller;
		setPopupMenuData(new MenuData(new String[] { "Edit Data Type..." }, "Decompile"));
//		setKeyBindingData( new KeyBindingData( KeyEvent.VK_L, InputEvent.CTRL_DOWN_MASK ) );

	}

	@Override
	public boolean isValidContext(ActionContext context) {
		return (context instanceof DecompilerActionContext);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			return false;
		}

		Function function = controller.getFunction();
		if (function instanceof UndefinedFunction) {
			return false;
		}

		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return false;
		}
		if (!tokenAtCursor.isVariableRef()) {
			return false;
		}
		HighVariable variable = tokenAtCursor.getHighVariable();
		if (variable == null) {
			return false;
		}
		DataType dataType = variable.getDataType();
		if (dataType == null) {
			return false;
		}
		return hasCustomEditorForBaseDataType(dataType);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			// Let this through here and handle it in actionPerformed().  This lets us alert 
			// the user that they have to wait until the decompile is finished.  If we are not
			// enabled at this point, then the keybinding will be propagated to the global 
			// actions, which is not what we want.
			return true;
		}

		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return false;
		}
		if (!tokenAtCursor.isVariableRef()) {
			return false;
		}
		HighVariable variable = tokenAtCursor.getHighVariable();
		if (variable == null) {
			return false;
		}
		DataType dataType = variable.getDataType();
		return hasCustomEditorForBaseDataType(dataType);
	}

	private boolean hasCustomEditorForBaseDataType(DataType dataType) {
		DataType baseDataType = DataTypeUtils.getBaseDataType(dataType);
		final DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		return baseDataType != null && service.isEditable(baseDataType);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// Note: we intentionally do this check here and not in isEnabledForContext() so 
		// that global events do not get triggered.
		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			Msg.showInfo(getClass(),
				context.getComponentProvider().getComponent(),
				"Decompiler Action Blocked", "You cannot perform Decompiler actions while the Decompiler is busy");
			return;
		}

		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		HighVariable variable = tokenAtCursor.getHighVariable();

		DataType dataType = variable.getDataType();
		DataType baseDataType = DataTypeUtils.getBaseDataType(dataType);
		DataTypeManager dataTypeManager = decompilerActionContext.getProgram().getDataTypeManager();
		DataTypeManager baseDtDTM = baseDataType.getDataTypeManager();
		if (baseDtDTM != dataTypeManager) {
			baseDataType = baseDataType.clone(dataTypeManager);
		}
		final DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		service.edit(baseDataType);
	}

}
