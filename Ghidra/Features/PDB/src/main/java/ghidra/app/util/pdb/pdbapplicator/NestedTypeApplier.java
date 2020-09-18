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
 * Applier for {@link AbstractNestedTypeMsType} and {@link AbstractNestedTypeExtMsType} types.
 */
public class NestedTypeApplier extends MsTypeApplier {

	private MsTypeApplier nestedTypeDefinitionApplier = null;

	/**
	 * Constructor for nested type applier.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractNestedTypeMsType} or {@link AbstractNestedTypeExtMsType} to
	 * process.
	 * @throws IllegalArgumentException Upon invalid arguments.
	 */
	public NestedTypeApplier(PdbApplicator applicator, AbstractMsType msType)
			throws IllegalArgumentException {
		super(applicator, validateType(msType));
	}

	@Override
	BigInteger getSize() {
		if (nestedTypeDefinitionApplier == null) {
			return BigInteger.ZERO;
		}
		return nestedTypeDefinitionApplier.getSize();
	}

	/**
	 * Returns the name of this nested type.
	 * @return Name of the nested type.
	 */
	String getTypeName() {
		if (nestedTypeDefinitionApplier == null) {
			return "";
		}
		return nestedTypeDefinitionApplier.getMsType().getName();
	}

	/**
	 * Returns the nested (member?) name for this nested type.
	 * @return (Member?) Name for the nested type.
	 */
	String getMemberName() {
		if (nestedTypeDefinitionApplier == null) {
			return "";
		}
		if (msType instanceof AbstractNestedTypeMsType) {
			return ((AbstractNestedTypeMsType) msType).getName();
		}
		return ((AbstractNestedTypeExtMsType) msType).getName();
	}

	MsTypeApplier getNestedTypeDefinitionApplier() {
		return applicator.getTypeApplier(getNestedTypeDefinitionRecordNumber());
	}

	RecordNumber getNestedTypeDefinitionRecordNumber() {
		if (msType instanceof AbstractNestedTypeMsType) {
			return ((AbstractNestedTypeMsType) msType).getNestedTypeDefinitionRecordNumber();
		}
		return ((AbstractNestedTypeExtMsType) msType).getNestedTypeDefinitionRecordNumber();
	}

	/**
	 * Indicates if there are attributes. Returns false if not "applied" yet.
	 * @return [@code true} if there are attributes.
	 */
	boolean hasAttributes() {
		if (nestedTypeDefinitionApplier == null) {
			return false;
		}
		if (nestedTypeDefinitionApplier.getMsType() instanceof AbstractNestedTypeMsType) {
			return false;
		}
		return true;
	}

	/**
	 * Returns the attributes if they exist.
	 * @return the attributes or null if they do not exist.
	 */
	ClassFieldMsAttributes getAttributes() {
		AbstractMsType type = nestedTypeDefinitionApplier.getMsType();
		if (type instanceof AbstractNestedTypeExtMsType) {
			return ((AbstractNestedTypeExtMsType) type).getClassFieldAttributes();
		}
		return null;
	}

	@Override
	void apply() throws PdbException, CancelledException {
		if (msType instanceof AbstractNestedTypeMsType) {
			dataType = applyNestedTypeMsType((AbstractNestedTypeMsType) msType);
		}
		else {
			dataType = applyNestedTypeExtMsType((AbstractNestedTypeExtMsType) msType);
		}
	}

	private DataType applyNestedTypeMsType(AbstractNestedTypeMsType type) {
		nestedTypeDefinitionApplier =
			applicator.getTypeApplier(type.getNestedTypeDefinitionRecordNumber());
		return nestedTypeDefinitionApplier.getDataType();
	}

	private DataType applyNestedTypeExtMsType(AbstractNestedTypeExtMsType type) {
		nestedTypeDefinitionApplier =
			applicator.getTypeApplier(type.getNestedTypeDefinitionRecordNumber());
		return nestedTypeDefinitionApplier.getDataType();
	}

//	ghDataTypeDB = applicator.resolve(dataType);

//	boolean underlyingIsCycleBreakable() {
//		// TODO: need to deal with InterfaceTypeApplier (will it be incorporated into
//		// CompostieTypeapplier?) Is it in this list of places to break (i.e., can it contain)?
//		return (modifiedTypeApplier != null &&
//			(modifiedTypeApplier instanceof CompositeTypeApplier ||
//				modifiedTypeApplier instanceof EnumTypeApplier));
//	}

	@Override
	DataType getCycleBreakType() {
		// hope to eliminate the null check if/when modifierTypeApplier is created at time of
		// construction
		//TODO: look into this
		return dataType;
//		if (modifiedTypeApplier == null) {
//			return null;
//		}
//		return modifiedTypeApplier.getCycleBreakType(applicator);
	}

	MsTypeApplier getNestedTypeApplier() {
		return nestedTypeDefinitionApplier;
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
