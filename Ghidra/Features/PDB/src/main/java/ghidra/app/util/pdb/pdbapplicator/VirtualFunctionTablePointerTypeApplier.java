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
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractVirtualFunctionTablePointerMsType} and
 * {@link AbstractVirtualFunctionTablePointerWithOffsetMsType} types.
 */
public class VirtualFunctionTablePointerTypeApplier extends MsTypeApplier {

	/**
	 * Constructor for enum type applier, for transforming a enum into a
	 * Ghidra DataType.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractVirtualFunctionTablePointerMsType} or 
	 * {@link AbstractVirtualFunctionTablePointerWithOffsetMsType} to process.
	 * @throws IllegalArgumentException Upon invalid arguments.
	 */
	public VirtualFunctionTablePointerTypeApplier(PdbApplicator applicator, AbstractMsType msType)
			throws IllegalArgumentException {
		super(applicator, validateType(msType));
	}

	@Override
	BigInteger getSize() {
		return BigInteger.valueOf(applicator.getDataOrganization().getPointerSize());
	}

	/**
	 * Returns the offset of the Virtual Function Table Pointer.
	 * @return Name of the nested type.
	 */
	int getOffset() {
		if (msType instanceof AbstractVirtualFunctionTablePointerWithOffsetMsType) {
			return ((AbstractVirtualFunctionTablePointerWithOffsetMsType) msType).getOffset();
		}
		return 0;
	}

	/**
	 * Returns the name to use.
	 * @return Name of the pointer type.
	 */
	String getMemberName() {
		return "VFTablePtr" + getOffset();
	}

	@Override
	void apply() throws PdbException, CancelledException {
		if (msType instanceof AbstractVirtualFunctionTablePointerMsType) {
			dataType = applyPointer(
				((AbstractVirtualFunctionTablePointerMsType) msType).getPointerTypeRecordNumber());
		}
		else {
			dataType = applyPointer(
				((AbstractVirtualFunctionTablePointerWithOffsetMsType) msType).getPointerTypeRecordNumber());
		}
	}

	private DataType applyPointer(RecordNumber pointerTypeRecordNumber) {
		MsTypeApplier rawApplier = applicator.getTypeApplier(pointerTypeRecordNumber);
		if (rawApplier instanceof PointerTypeApplier) {
			return rawApplier.getDataType();
		}
		applicator.appendLogMsg("cannot process " + rawApplier.getClass().getSimpleName() + "for " +
			getClass().getSimpleName());
		return null;
	}

	private static AbstractMsType validateType(AbstractMsType type)
			throws IllegalArgumentException {
		if (!(type instanceof AbstractVirtualFunctionTablePointerMsType) &&
			!(type instanceof AbstractVirtualFunctionTablePointerWithOffsetMsType)) {
			throw new IllegalArgumentException(
				"PDB Incorrectly applying " + type.getClass().getSimpleName() + " to " +
					VirtualFunctionTablePointerTypeApplier.class.getSimpleName());
		}
		return type;
	}

}
