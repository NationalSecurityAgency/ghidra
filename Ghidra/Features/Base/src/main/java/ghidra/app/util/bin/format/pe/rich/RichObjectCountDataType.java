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
package ghidra.app.util.bin.format.pe.rich;

import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;

class RichObjectCountDataType extends DataTypeImpl {

	private final int count;

	public RichObjectCountDataType(int count) {
		this(count, null);
	}

	public RichObjectCountDataType(int count, DataTypeManager dtm) {
		super(new CategoryPath("/PE"), "RichObjectCount", dtm);
		this.count = count;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new RichObjectCountDataType(count, dtm);
	}

	@Override
	public DataType copy(DataTypeManager dtm) {
		return clone(dtm);
	}

	@Override
	public void setCategoryPath(CategoryPath path) throws DuplicateNameException {
		// ignored
	}

	@Override
	public void setName(String name) throws InvalidNameException {
		// ignored
	}

	@Override
	public void setNameAndCategory(CategoryPath path, String name)
			throws InvalidNameException, DuplicateNameException {
		// ignored
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "xorddw";
	}

	@Override
	public int getLength() {
		return 4;
	}

	@Override
	public String getDescription() {
		return null;
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return count;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return "" + count;
	}

	@Override
	public boolean isEquivalent(DataType dt) {
		if (dt == this) {
			return true;
		}
		if (dt == null) {
			return false;
		}
		return getClass() == dt.getClass();
	}

	@Override
	public void dataTypeSizeChanged(DataType dt) {
		// ignored
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		// ignored			
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		// ignored
	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
		// ignored
	}

	@Override
	public boolean dependsOn(DataType dt) {
		return false;
	}
}
