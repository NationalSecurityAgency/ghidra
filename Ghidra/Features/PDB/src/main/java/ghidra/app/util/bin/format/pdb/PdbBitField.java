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
package ghidra.app.util.bin.format.pdb;

import ghidra.program.model.data.*;
import ghidra.util.exception.AssertException;

/**
 * <code>PdbBitField</code> provides ability to hang onto bitfield as a datatype.
 * This will be transformed to a normal BitFieldDataType when cloned.
 */
public class PdbBitField extends BitFieldDataType {

	private int bitOffsetWithinBaseType;

	// TODO: add support for big-endian

	/**
	 * Construct a PDB bitfield (not intended for direct use by DataTypeManager)
	 * @param baseDataType fielfield base datatype cloned for target datatype manager
	 * @param bitSize bitfield size in bits
	 * @param bitOffsetWithinBaseType bit offset within baseDataType or -1 if unknown
	 * @throws InvalidDataTypeException if invalid bitfield parameters are specified
	 */
	protected PdbBitField(DataType baseDataType, int bitSize, int bitOffsetWithinBaseType)
			throws InvalidDataTypeException {
		super(baseDataType, bitSize,
			getMinimalBitOffset(baseDataType, bitSize, bitOffsetWithinBaseType));
		if (bitSize < 1) {
			throw new InvalidDataTypeException("invalid PDB bit size: " + bitSize);
		}
		if (bitOffsetWithinBaseType < -1) {
			throw new InvalidDataTypeException(
				"invalid PDB bit offset: " + bitOffsetWithinBaseType);
		}
		this.bitOffsetWithinBaseType = bitOffsetWithinBaseType;
	}

	private static int getMinimalBitOffset(DataType baseDataType, int bitSize,
			int bitOffsetWithinBaseType) {
		if (bitOffsetWithinBaseType < 0) {
			return 0;
		}
		// assumes little endian packing (lsb first)
		return bitOffsetWithinBaseType % 8;
	}

	/**
	 * Get the bit offset within the full base type
	 * @return base type bit offset or -1 if unknown
	 */
	public int getBitOffsetWithinBase() {
		return bitOffsetWithinBaseType;
	}

	@Override
	public BitFieldDataType clone(DataTypeManager dtm) {
		if (dtm != getDataTypeManager()) {
			throw new AssertException("unsupported clone operation");
		}
		return this;
	}

	@Override
	public String toString() {
		return getDisplayName() + "(baseSize:" + getBaseTypeSize() + ",bitOffsetInBase:" +
			bitOffsetWithinBaseType + ")";
	}

}
