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
package ghidra.app.util.pdb.pdbapplicator;

import ghidra.app.util.bin.format.pdb.*;
import ghidra.app.util.pdb.classtype.ClassFieldAttributes;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.CancelledException;

/**
 * <code>PdbMember</code> convey PDB member information used for datatype
 * reconstruction.
 */
public class DefaultPdbUniversalMember extends PdbMember {

	private DataType dataType;
	private ClassFieldAttributes attributes;
	private boolean isZeroLengthArray;

	/**
	 * Default PDB member construction
	 * @param name member field name.  For bitfields this also conveys the bit-size
	 * and optionally the bit-offset.
	 * @param dataType for the field.
	 * @param offset member's byte offset within the root composite.
	 */
	DefaultPdbUniversalMember(String name, DataType dataType, int offset) {
		super(name, dataType.getName(), offset, null);
		this.dataType = dataType;
		this.attributes = ClassFieldAttributes.BLANK;
		this.isZeroLengthArray = false;
	}

	/**
	 * Default PDB member construction
	 * @param name member field name.  For bitfields this also conveys the bit-size
	 * and optionally the bit-offset.
	 * @param dataType for the field.
	 * @param isZeroLengthArray indicates if, when an array, it is a zero-length (flex) array
	 * @param offset member's byte offset within the root composite.
	 * @param attributes the attributes of the member
	 * @param memberComment optional member comment (may be null)
	 */
	DefaultPdbUniversalMember(String name, DataType dataType, boolean isZeroLengthArray, int offset,
			ClassFieldAttributes attributes, String memberComment) {
		super(name, dataType.getName(), offset, memberComment);
		this.dataType = dataType;
		this.attributes = attributes;
		this.isZeroLengthArray = isZeroLengthArray;
	}

	private DataType getDataTypeInternal() {
		return dataType;
	}

	public boolean isZeroLengthArray() {
		return isZeroLengthArray;
	}

	public ClassFieldAttributes getAttributes() {
		return attributes;
	}

	@Override
	public String getDataTypeName() {
		return getDataTypeInternal().getName();
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("name=");
		builder.append(getName());

		DataType dt = getDataTypeInternal();
		if (dt instanceof PdbBitField) {
			PdbBitField bfDt = (PdbBitField) dt;
			builder.append(", type=");
			builder.append(bfDt.getBaseDataType().getName());
			builder.append(", offset=");
			builder.append(getOffset());
			builder.append(", bitSize=");
			builder.append(bfDt.getDeclaredBitSize());
			builder.append(", bitOffset=");
			builder.append(bfDt.getBitOffsetWithinBase());
		}
		else {
			builder.append(", type=");
			builder.append(dt.getName());
			builder.append(", offset=");
			builder.append(getOffset());
		}
		return builder.toString();
	}

	@Override
	protected WrappedDataType getDataType() throws CancelledException {
		DataType dt = getDataTypeInternal();
		return new WrappedDataType(dt, isZeroLengthArray, false);
	}

}
