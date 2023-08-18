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
 * Applier for {@link AbstractNestedTypeMsType} and {@link AbstractNestedTypeExtMsType} types.
 */
public class NestedTypeApplier extends MsTypeApplier {

	// Intended for: AbstractNestedTypeMsType or AbstractNestedTypeExtMsType
	/**
	 * Constructor for nested type applier
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working
	 * @throws IllegalArgumentException upon invalid arguments
	 */
	public NestedTypeApplier(DefaultPdbApplicator applicator)
			throws IllegalArgumentException {
		super(applicator);
	}

	/**
	 * Returns the nested (member?) name for this nested type
	 * @param type the PDB type being inspected
	 * @return (member?) name for the nested type
	 */
	String getMemberName(AbstractMsType type) {

		if (type instanceof AbstractNestedTypeMsType nested) {
			return nested.getName();
		}
		else if (type instanceof AbstractNestedTypeExtMsType nestedExt) {
			return nestedExt.getName();
		}
		return "";
	}

	@Override
	DataType apply(AbstractMsType type, FixupContext fixupContext, boolean breakCycle)
			throws PdbException, CancelledException {
		RecordNumber typeRecordNumber;
		if (type instanceof AbstractNestedTypeMsType nestedType) {
			typeRecordNumber = nestedType.getNestedTypeDefinitionRecordNumber();
		}
		else if (type instanceof AbstractNestedTypeExtMsType extNestedType) {
			typeRecordNumber = extNestedType.getNestedTypeDefinitionRecordNumber();
		}
		else {
			throw new PdbException(
				"Unexpected nested type in field list: " + type.getClass().getSimpleName());
		}
		AbstractMsType mType = applicator.getPdb().getTypeRecord(typeRecordNumber);
		MsTypeApplier applier = applicator.getTypeApplier(typeRecordNumber);
		return applier.apply(mType, fixupContext, breakCycle);
	}

	private static AbstractMsType validateType(AbstractMsType type)
			throws IllegalArgumentException {
		if (!(type instanceof AbstractNestedTypeMsType) &&
			!(type instanceof AbstractNestedTypeExtMsType)) {
			throw new IllegalArgumentException("PDB Incorrectly applying " +
				type.getClass().getSimpleName() + " to " + NestedTypeApplier.class.getSimpleName());
		}
		return type;
	}
}
