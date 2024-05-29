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

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.util.exception.CancelledException;

/**
 * Abstract class representing the applier for a specific PDB_ID type, distinguished as
 *  representing an actual data type... not a component of a data type for which there is
 *  no associated type.
 */
public abstract class MsDataTypeApplier extends MsTypeApplier {

	/**
	 * Constructor.
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working.
	 */
	public MsDataTypeApplier(DefaultPdbApplicator applicator) {
		super(applicator);
	}

	/**
	 * Apply the {@link AbstractMsType} in an attempt to create a Ghidra type
	 * @param type the PDB type to work on
	 * @return the {@code true} if type is done and can be removed from the {@code todoStack}
	 * @throws PdbException if there was a problem processing the data.
	 * @throws CancelledException upon user cancellation
	 */
	abstract boolean apply(AbstractMsType type) throws PdbException, CancelledException;

	/**
	 * Returns the (long) size of the type or 0 if unknown. Or Long.MAX_VALUE if too large.
	 * @param type the PDB type being inspected
	 * @return the size; zero if unknown.
	 */
	long getSizeLong(AbstractMsType type) {
		return applicator.bigIntegerToLong(type.getSize());
	}

	/**
	 * Returns the (int) size of the type or 0 if unknown. Or Integer.MAX_VALUE if too large.
	 * @param type the PDB type being inspected
	 * @return the size; zero if unknown.
	 */
	int getSizeInt(AbstractMsType type) {
		return applicator.bigIntegerToInt(type.getSize());
	}

	//==============================================================================================
	// TODO: Need to investigate if we adopt the following... if so, should use them consistently.

//	/**
//	 * Convenience method for getting the {@link DataType} from the applicator pertaining
//	 * to this PDB type
//	 * @param type the PDB type
//	 * @return the ghidra data type
//	 */
//	DataType getDataType(AbstractMsType type) {
//		return applicator.getDataType(type);
//	}
//
//	protected int getIndex(AbstractMsType type) {
//		RecordNumber recordNumber = type.getRecordNumber();
//		if (recordNumber != null) {
//			return recordNumber.getNumber();
//		}
//		return -1;
//	}
}
