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

import ghidra.app.decompiler.ClangBitFieldToken;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class RenameStructBitFieldTask extends RenameTask {

	private ClangBitFieldToken token;
	private DataTypeComponent component;

	public RenameStructBitFieldTask(PluginTool tool, Program program, DecompilerProvider provider,
			ClangBitFieldToken token) {
		super(tool, program, provider, token, token.getText());
		this.token = token;
	}

	@Override
	public String getTransactionName() {
		return "Rename Structure BitField";
	}

	@Override
	public boolean isValid(String newNm) {
		newName = newNm;
		component = token.getComponent();
		if (component == null) {
			return false;
		}
		Composite structure = (Composite) token.getDataType();
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

	@Override
	public void commit() throws DuplicateNameException, InvalidInputException {
		component.setFieldName(newName);
	}
}
