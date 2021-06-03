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
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class RenameStructureFieldTask extends RenameTask {

	private Structure structure;
	public int offset;

	public RenameStructureFieldTask(PluginTool tool, Program program, DecompilerPanel panel,
			ClangToken token, Structure structure, int offset) {
		super(tool, program, panel, token, token.getText());
		this.structure = structure;
		this.offset = offset;
	}

	@Override
	public void commit() throws DuplicateNameException, InvalidInputException {
		// FIXME: How should an existing packed structure be handled? Growing and offset-based placement does not apply
		int len = structure.isZeroLength() ? 0 : structure.getLength();
		if (len < offset) {
			if (!structure.isPackingEnabled()) {
				Msg.warn(this, "Structure '" + structure.getName() + "' converted to non-packed");
				structure.setPackingEnabled(false);
			}
			structure.growStructure(offset);
		}
		DataTypeComponent comp = structure.getComponentAt(offset);
		if (comp.getDataType() == DataType.DEFAULT) {		// Is this just a placeholder
			DataType newtype = new Undefined1DataType();
			structure.replaceAtOffset(offset, newtype, 1, newName, "Created by retype action");
		}
		else {
			comp.setFieldName(newName);
		}
	}

	@Override
	public String getTransactionName() {
		return "Rename Structure Field";
	}

	@Override
	public boolean isValid(String newNm) {
		newName = newNm;
		DataTypeComponent[] comp = structure.getDefinedComponents();
		for (DataTypeComponent element : comp) {
			String fieldname = element.getFieldName();
			if (fieldname == null) {
				continue;
			}
			if (fieldname.equals(newName)) {
				errorMsg = "Duplicate Field Name";
				return false;
			}
		}
		return true;
	}

}
