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

class MSRichProductIDDataType extends DataTypeImpl {

	private final CompId compid;

	public MSRichProductIDDataType(CompId compid) {
		this(compid, null);
	}

	public MSRichProductIDDataType(CompId compid, DataTypeManager dtm) {
		super(new CategoryPath("/PE"), "MSProductID", dtm);
		this.compid = compid;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new MSRichProductIDDataType(compid, dtm);
	}

	@Override
	public DataType copy(DataTypeManager dtm) {
		return clone(dtm);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "Product ID";
	}

	@Override
	public int getLength() {
		return 2;
	}

	@Override
	public String getDescription() {
		return "Product ID";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return compid.getProductId();
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {

		return compid.getProductDescription();

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

}
