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
package ghidra.app.plugin.core.stackeditor;

import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;

public class StackPieceDataType extends DataTypeImpl {

	private final Variable variable;

	StackPieceDataType(Variable var, DataTypeManager dataMgr) {
		super(CategoryPath.ROOT, getPieceName(var), dataMgr);
		variable = var;
	}

	private static String getPieceName(Variable var) {
		VariableStorage storage = var.getVariableStorage();
		Varnode stackVarnode = storage.getLastVarnode();
		int pieceLen = stackVarnode.getSize();
		return var.getDataType().getName() + ":" + pieceLen + " (piece)";
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		throw new IllegalArgumentException("May not be cloned with new DataTypeManager");
	}

	@Override
	public DataType copy(DataTypeManager dtm) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setCategoryPath(CategoryPath path) throws DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setName(String name) throws InvalidNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setNameAndCategory(CategoryPath path, String name)
			throws InvalidNameException, DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getMnemonic(Settings settings) {
		DataType dt = variable.getDataType();
		return dt.getMnemonic(settings) + ":" + getLength();
	}

	@Override
	public int getLength() {
		VariableStorage storage = variable.getVariableStorage();
		Varnode stackVarnode = storage.getLastVarnode();
		return stackVarnode.getSize();
	}

	@Override
	public String getDescription() {
		// We could provide a description if needed
		return null;
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return null;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return null;
	}

	@Override
	public boolean isEquivalent(DataType dt) {
		return false;
	}

	@Override
	public void dataTypeSizeChanged(DataType dt) {
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
	}

	@Override
	public boolean dependsOn(DataType dt) {
		return false;
	}

}
