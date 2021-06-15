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
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractBaseClassMsType}, {@link AbstractVirtualBaseClassMsType}, and
 * {@link AbstractIndirectVirtualBaseClassMsType} types.
 */
public class UdtSourceLineTypeApplier extends MsTypeApplier {

	/**
	 * Constructor for base class applier.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractBaseClassMsType}, {@link AbstractVirtualBaseClassMsType}, or
	 * {@link AbstractIndirectVirtualBaseClassMsType} to processes.
	 * @throws IllegalArgumentException Upon invalid arguments.
	 */
	public UdtSourceLineTypeApplier(PdbApplicator applicator, AbstractMsType msType)
			throws IllegalArgumentException {
		super(applicator, validateType(msType));
	}

	// The MsTypes for which we are working do not have a size in and of themselves, but the
	//  classes/structures to which they refer have a size, even if zero.
	// For here, we are only reporting what "we" have, not what the underlying sizes are.
	// ...and a value of zero is our "don't know" and "not represented" value.
	@Override
	BigInteger getSize() {
		return BigInteger.ZERO;
	}

	/**
	 * Returns the offset of the Base Class within the inheriting class.
	 * @return the offset.
	 */
	int getLineNumber() {
		if (msType instanceof UserDefinedTypeSourceAndLineMsType) {
			return ((UserDefinedTypeSourceAndLineMsType) msType).getLineNumber();
		}
		return ((UserDefinedTypeModuleSourceAndLineMsType) msType).getLineNumber();
	}

	/**
	 * Returns the source file name.
	 * @return the source file name.  null if problem recovering name.
	 */
	String getSourceFileName() {
		if (msType instanceof UserDefinedTypeSourceAndLineMsType) {
			return ((UserDefinedTypeSourceAndLineMsType) msType).getSourceFileName();
		}
		return ((UserDefinedTypeModuleSourceAndLineMsType) msType).getSourceFileName();
	}

	/**
	 * Returns the record number of the UDT.
	 * @return the record number of the UDT.
	 */
	RecordNumber getUdtRecordNumber() {
		if (msType instanceof UserDefinedTypeSourceAndLineMsType) {
			return ((UserDefinedTypeSourceAndLineMsType) msType).getUdtRecordNumber();
		}
		return ((UserDefinedTypeModuleSourceAndLineMsType) msType).getUdtRecordNumber();
	}

	@Override
	void apply() throws PdbException, CancelledException {
		String filename = getSourceFileName();
		int lineNumber = getLineNumber();
		RecordNumber udtRecordNumber = getUdtRecordNumber();
		MsTypeApplier typeApplier = applicator.getTypeApplier(udtRecordNumber);

		// do nothing at the moment.
		applicator.putRecordNumberByFileName(udtRecordNumber, filename);
		if (msType instanceof UserDefinedTypeModuleSourceAndLineMsType) {
			int moduleNumber =
				((UserDefinedTypeModuleSourceAndLineMsType) msType).getModuleNumber();
			applicator.putRecordNumberByModuleNumber(udtRecordNumber, moduleNumber);
		}
	}

	private static AbstractMsType validateType(AbstractMsType type)
			throws IllegalArgumentException {
		if (!(type instanceof UserDefinedTypeSourceAndLineMsType) &&
			!(type instanceof UserDefinedTypeModuleSourceAndLineMsType)) {
			throw new IllegalArgumentException(
				"PDB Incorrectly applying " + type.getClass().getSimpleName() + " to " +
					UdtSourceLineTypeApplier.class.getSimpleName());
		}
		return type;
	}

}
