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

import docking.widgets.OptionDialog;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

public class RetypeUnionFieldTask extends RetypeFieldTask {

	private DataTypeComponent component;
	private int ordinal;

	public RetypeUnionFieldTask(PluginTool tool, Program program, DecompilerProvider provider,
			ClangToken token, Composite composite) {
		super(tool, program, provider, token, composite);
	}

	@Override
	public String getTransactionName() {
		return "Retype Union Field";
	}

	@Override
	public boolean isValidBefore() {
		if (!(composite instanceof Union)) {
			errorMsg = "Could not identify union at cursor";
			return false;
		}

		ordinal = ((ClangFieldToken) tokenAtCursor).getOffset();
		component = composite.getComponent(ordinal);
		if (component == null) {
			errorMsg = "Could not identify component of " + composite.getName();
			return false;
		}
		oldType = component.getDataType();
		if (oldType instanceof BitFieldDataType) {
			errorMsg = "Retype of defined bit-field is not supported.";
			return false;
		}
		return true;
	}

	/**
	 * @return true if the new field data-type will cause the size of the union to change
	 */
	private boolean hasSizeChange() {
		int newTypeLength = newType.getLength();
		if (newTypeLength == composite.getLength()) {
			return false;
		}
		if (newType.getLength() < composite.getLength()) {
			DataTypeComponent[] components = composite.getDefinedComponents();
			for (DataTypeComponent dtc : components) {
				if (dtc.getOffset() + dtc.getLength() > newTypeLength) {
					return false;
				}
			}
		}
		return true;
	}

	@Override
	public boolean isValidAfter() {
		// check for permitted datatype
		if (newType instanceof FactoryDataType || newType.getLength() <= 0) {
			errorMsg = "Field of type '" + newType.getName() + "' - is not allowed.";
			return false;
		}
		if (hasSizeChange()) {
			int choice = OptionDialog.showOptionDialogWithCancelAsDefaultButton(null,
				"Increase the size of the union",
				"The size of the containing union will be changed if you continue.", "Continue",
				OptionDialog.WARNING_MESSAGE);
			if (choice != OptionDialog.OPTION_ONE) {
				return false;
			}
		}
		return true;
	}

	@Override
	public void commit() throws IllegalArgumentException {
		String fieldName = null;
		String comment = null;
		if (component != null) {
			fieldName = component.getFieldName();
			comment = component.getComment();
		}
		composite.delete(ordinal);
		composite.insert(ordinal, newType, -1, fieldName, comment);
	}

}
