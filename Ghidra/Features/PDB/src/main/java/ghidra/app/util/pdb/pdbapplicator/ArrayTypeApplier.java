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

import java.math.BigInteger;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractArrayMsType;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractArrayMsType} types.
 */
public class ArrayTypeApplier extends MsDataTypeApplier {

	// Intended for: AbstractArrayMsType
	/**
	 * Constructor for the applicator that applies a "array" type, transforming it into a
	 * Ghidra DataType
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working
	 */
	public ArrayTypeApplier(DefaultPdbApplicator applicator) {
		super(applicator);
	}

	@Override
	boolean apply(AbstractMsType type) throws PdbException, CancelledException {

		AbstractArrayMsType arrayType = (AbstractArrayMsType) type;
		// Doing pre-check on type first using the getDataTypeOrSchedule method.  The logic is
		//  simpler here for Composites or Functions because we only have one dependency type,
		//  so we are not doing a separate call to a pre-check method as there is in those appliers.
		//  If type is not available, return false.
		RecordNumber underlyingRecordNumber = arrayType.getElementTypeRecordNumber();
		DataType underlyingDataType = applicator.getDataTypeOrSchedule(underlyingRecordNumber);
		if (underlyingDataType == null) {
			return false;
		}

		int numElements = calculateNumElements(arrayType, underlyingDataType);
		if (numElements == -1) {
			// There was a math calculation problem (probably have the wrong underlying type,
			// which we still need to figure out; i.e., better composite mapper) so we
			// will change the underlying type for now...
			underlyingDataType = Undefined1DataType.dataType;
			numElements = getSizeInt(arrayType); // array size (but divided by 1) is array size
		}
		DataType dataType = new ArrayDataType(underlyingDataType, numElements, -1,
			applicator.getDataTypeManager());
		applicator.putDataType(arrayType, dataType);
		return true;
	}

	boolean isFlexibleArray(AbstractMsType type) {
		return BigInteger.ZERO.equals(type.getSize());
	}

	private int calculateNumElements(AbstractArrayMsType type, DataType underlyingDataType) {

		if (underlyingDataType == null) {
			// TODO: test and clean up... can this happen?
			underlyingDataType = Undefined1DataType.dataType;
			String msg = "PDB Type index " + type.getRecordNumber().getNumber() +
				":\n   Null underlying data type for " + type.getClass().getSimpleName() +
				":\n      " + type.getName() + "\n   Using " + underlyingDataType;
			Msg.warn(this, msg);
		}

		long longUnderlyingSize = underlyingDataType.getLength();

		if (longUnderlyingSize > Integer.MAX_VALUE) {
			String msg = "PDB " + type.getClass().getSimpleName() + ": Underlying type too large " +
				underlyingDataType.getName();
			Msg.warn(this, msg);
			underlyingDataType = Undefined1DataType.dataType;
			longUnderlyingSize = 1L;
		}
		else if (longUnderlyingSize == 0L) {
			longUnderlyingSize = 1L;
		}

		long longArraySize = getSizeLong(type);
		long longNumElements = longArraySize / longUnderlyingSize;

		if (longNumElements > Integer.MAX_VALUE) {
			String msg = "PDB " + type.getClass().getSimpleName() +
				": Array num elements too large: " + longUnderlyingSize;
			Msg.warn(this, msg);
			longNumElements = 1L;
		}
		else if (longArraySize == 0) {
			//flexible array
			longNumElements = 0L;
		}
		else if (longArraySize % longUnderlyingSize != 0L) {
			String msg = "PDB " + type.getClass().getSimpleName() +
				": Array num elements calculation error underlying type " + longArraySize + " % " +
				longUnderlyingSize;
			Msg.warn(this, msg);
			// bad calculation.  Underlying type does not evenly fit into array total size.
			return -1;
		}

		int numElements = (int) longNumElements;

		return numElements;
	}

}
