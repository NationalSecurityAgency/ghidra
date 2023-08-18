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
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractBaseClassMsType}, {@link AbstractVirtualBaseClassMsType}, and
 * {@link AbstractIndirectVirtualBaseClassMsType} types.
 */
public class UdtSourceLineTypeApplier extends MsTypeApplier {

	// Intended for: UserDefinedTypeSourceAndLineMsType or UserDefinedTypeModuleSourceAndLineMsType
	/**
	 * Constructor for base class applier.
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working.
	 * @throws IllegalArgumentException Upon invalid arguments.
	 */
	public UdtSourceLineTypeApplier(DefaultPdbApplicator applicator)
			throws IllegalArgumentException {
		super(applicator);
	}

	/**
	 * Returns the offset of the Base Class within the inheriting class
	 * @param type the PDB type being inspected
	 * @return the offset or -1 if problem retrieving value
	 */
	int getLineNumber(AbstractMsType type) {
		if (type instanceof UserDefinedTypeSourceAndLineMsType udtSLType) {
			return udtSLType.getLineNumber();
		}
		else if (type instanceof UserDefinedTypeModuleSourceAndLineMsType udtMSLType) {
			return udtMSLType.getLineNumber();
		}
		return -1;
	}

	/**
	 * Returns the source file name
	 * @param type the PDB type being inspected
	 * @return the source file name or null if problem recovering name
	 */
	String getSourceFileName(AbstractMsType type) {
		if (type instanceof UserDefinedTypeSourceAndLineMsType udtSLType) {
			return udtSLType.getSourceFileName();
		}
		else if (type instanceof UserDefinedTypeModuleSourceAndLineMsType udtMSLType) {
			return udtMSLType.getSourceFileName();
		}
		return null;
	}

	/**
	 * Returns the record number of the UDT
	 * @param type the PDB type being inspected
	 * @return the record number of the UDT or null if problem retrieving value
	 */
	RecordNumber getUdtRecordNumber(AbstractMsType type) {
		if (type instanceof UserDefinedTypeSourceAndLineMsType udtSLType) {
			return udtSLType.getUdtRecordNumber();
		}
		else if (type instanceof UserDefinedTypeModuleSourceAndLineMsType udtMSLType) {
			return udtMSLType.getUdtRecordNumber();
		}
		return null;
	}

	@Override
	DataType apply(AbstractMsType type, FixupContext fixupContext, boolean breakCycle)
			throws PdbException, CancelledException {
		String filename = getSourceFileName(type);
		int lineNumber = getLineNumber(type);
		RecordNumber udtRecordNumber = getUdtRecordNumber(type);
		MsTypeApplier typeApplier = applicator.getTypeApplier(udtRecordNumber);

		// do nothing at the moment.
		applicator.putRecordNumberByFileName(udtRecordNumber, filename);
		if (type instanceof UserDefinedTypeModuleSourceAndLineMsType) {
			int moduleNumber = ((UserDefinedTypeModuleSourceAndLineMsType) type).getModuleNumber();
			applicator.putRecordNumberByModuleNumber(udtRecordNumber, moduleNumber);
		}
		return null;
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
