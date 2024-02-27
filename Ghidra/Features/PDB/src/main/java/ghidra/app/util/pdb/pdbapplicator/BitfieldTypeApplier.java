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

import ghidra.app.util.bin.format.pdb.PdbBitField;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractBitfieldMsType;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractBitfieldMsType} types.
 */
public class BitfieldTypeApplier extends MsDataTypeApplier {

	// Intended for: AbstractBitfieldMsType
	/**
	 * Constructor for bitfield applier
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working
	 */
	public BitfieldTypeApplier(DefaultPdbApplicator applicator) {
		super(applicator);
	}

	@Override
	boolean apply(AbstractMsType type) throws PdbException, CancelledException {

		AbstractBitfieldMsType mType = (AbstractBitfieldMsType) type;
		// Doing pre-check on type first using the getDataTypeOrSchedule method.  The logic is
		//  simpler here for Composites or Functions because we only have one dependency type,
		//  so we are not doing a separate call to a pre-check method as there is in those appliers.
		//  If type is not available, return false.
		RecordNumber elementRecordNumber = mType.getElementRecordNumber();
		DataType baseDataType = applicator.getDataTypeOrSchedule(elementRecordNumber);
		if (baseDataType == null) {
			return false;
		}

		DataType bitFieldDataType;
		try {
			bitFieldDataType = new Pdb2BitField(baseDataType.clone(applicator.getDataTypeManager()),
				mType.getBitLength(), mType.getBitPosition());
		}
		catch (InvalidDataTypeException e) {
			throw new PdbException(
				"Problem creating PdbBitField for " + type.getName() + ", error: " + e.toString());
		}
		applicator.putDataType(mType, bitFieldDataType);
		return true;
	}

	/**
	 * <code>Pdb2BitField</code> provides ability to hang onto bitfield as a datatype.
	 * This will be transformed to a normal BitFieldDataType when cloned.
	 */
	private class Pdb2BitField extends PdbBitField {
		private Pdb2BitField(DataType baseDataType, int bitSize, int bitOffsetWithinBaseType)
				throws InvalidDataTypeException {
			super(baseDataType, bitSize, bitOffsetWithinBaseType);
		}
	}

}
