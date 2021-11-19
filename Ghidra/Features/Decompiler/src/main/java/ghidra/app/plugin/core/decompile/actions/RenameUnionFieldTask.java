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
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class RenameUnionFieldTask extends RenameTask {
	private Composite composite;
	private int ordinal;

	public RenameUnionFieldTask(PluginTool tool, Program program, DecompilerProvider provider,
			ClangToken token, Composite composite, int ordinal) {
		super(tool, program, provider, token, token.getText());
		this.composite = composite;
		this.ordinal = ordinal;
	}

	@Override
	public void commit() throws DuplicateNameException, InvalidInputException {
		DataTypeComponent dtc = composite.getComponent(ordinal);
		dtc.setFieldName(newName);
	}

	@Override
	public String getTransactionName() {
		return "Rename Union Field";
	}

	@Override
	public boolean isValid(String newNm) {
		newName = newNm;
		DataTypeComponent[] comp = composite.getDefinedComponents();
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
