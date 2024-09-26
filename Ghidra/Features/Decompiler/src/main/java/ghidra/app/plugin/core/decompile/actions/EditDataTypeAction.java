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
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.util.HelpLocation;
import ghidra.util.UndefinedFunction;

public class EditDataTypeAction extends AbstractDecompilerAction {

	public EditDataTypeAction() {
		super("Edit Data Type");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionEditDataType"));
		setPopupMenuData(new MenuData(new String[] { "Edit Data Type" }, "Decompile"));
	}

	@Override
	public boolean isValidContext(ActionContext context) {
		return (context instanceof DecompilerActionContext);
	}

	private boolean hasCustomEditorForBaseDataType(PluginTool tool, DataType dataType) {
		DataType baseDataType = DataTypeUtils.getBaseDataType(dataType);
		final DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		return baseDataType != null && service.isEditable(baseDataType);
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {

		Function function = context.getFunction();
		if (function instanceof UndefinedFunction) {
			return false;
		}

		DataType dataType = DecompilerUtils.getDataType(context);
		if (dataType == null) {
			return false;
		}

		return hasCustomEditorForBaseDataType(context.getTool(), dataType);
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {

		DataType dataType = DecompilerUtils.getDataType(context);
		DataType baseDataType = DataTypeUtils.getBaseDataType(dataType);
		DataTypeManager dataTypeManager = context.getProgram().getDataTypeManager();
		DataTypeManager baseDtDTM = baseDataType.getDataTypeManager();
		if (baseDtDTM != dataTypeManager) {
			baseDataType = baseDataType.clone(dataTypeManager);
		}

		DataTypeManagerService service =
			context.getTool().getService(DataTypeManagerService.class);

		if (dataType instanceof Structure structure) {
			editStructure(service, structure, context);
		}
		else {
			service.edit(baseDataType);
		}
	}

	private void editStructure(DataTypeManagerService service, Structure structure,
			DecompilerActionContext context) {

		DecompilerPanel decompilerPanel = context.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		if (tokenAtCursor instanceof ClangFieldToken) {
			String fieldName = tokenAtCursor.getText();
			if (fieldName != null) {
				service.edit(structure, fieldName);
				return;
			}
		}

		service.edit(structure);
	}
}
