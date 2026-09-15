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
import docking.action.*;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.data.EditDataFieldDialog;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.*;

/**
 * Performs a quick edit of a given field using the {@link EditDataFieldDialog}.   This action is
 * similar to the same named action available in the Listing.
 */
public class EditFieldAction extends AbstractDecompilerAction {

	public EditFieldAction() {
		super("Quick Edit Field", KeyBindingType.SHARED);

		setHelpLocation(new HelpLocation("DataPlugin", "Edit_Field_Dialog"));
		setPopupMenuData(new MenuData(new String[] { "Quick Edit Field..." }, "Decompile"));

		setKeyBindingData(new KeyBindingData("ctrl shift E"));
	}

	@Override
	public boolean isValidContext(ActionContext context) {
		return (context instanceof DecompilerActionContext);
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {

		Function function = context.getFunction();
		if (function instanceof UndefinedFunction) {
			return false;
		}

		Address address = context.getAddress();
		if (address == null) {
			return false;
		}

		ClangToken tokenAtCursor = context.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return false;
		}

		if (!(tokenAtCursor instanceof ClangFieldToken)) {
			return false;
		}

		Composite composite = getCompositeDataType(tokenAtCursor);
		if (composite == null) {
			return false;
		}

		int offset = ((ClangFieldToken) tokenAtCursor).getOffset();
		if (offset < 0 || offset >= composite.getLength()) {
			return false;
		}

		return true;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {

		ClangToken tokenAtCursor = context.getTokenAtCursor();
		Composite composite = getCompositeDataType(tokenAtCursor);
		ClangFieldToken token = (ClangFieldToken) tokenAtCursor;
		DataTypeComponent dtc = null;
		int offset = token.getOffset();
		String fieldName = token.getText();
		if (composite instanceof Structure structure) {
			dtc = structure.getComponentContaining(offset);
		}
		else if (composite instanceof Union union) {

			int n = union.getNumComponents();
			for (int i = 0; i < n; i++) {
				DataTypeComponent unionDtc = union.getComponent(i);
				String dtcName = unionDtc.getFieldName();
				if (fieldName.equals(dtcName)) {
					dtc = unionDtc;
					break;
				}
			}
		}

		if (dtc == null) {
			Msg.debug(this,
				"Unable to find field '%s' at offset %d in composite %s".formatted(fieldName,
					offset, composite.getName()));
			return;
		}

		Address address = context.getAddress();
		Program program = context.getProgram();
		int ordinal = dtc.getOrdinal();
		PluginTool tool = context.getTool();

		DataTypeManagerService service =
			tool.getService(DataTypeManagerService.class);
		EditDataFieldDialog dialog =
			new EditDataFieldDialog(tool, service, composite, program, address, ordinal);
		tool.showDialog(dialog);
	}

}
