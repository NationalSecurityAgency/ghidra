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

import java.util.List;

import ghidra.app.util.SymbolPath;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractEnumMsType} types.
 */
public class EnumTypeApplier extends AbstractComplexTypeApplier {

	// Intended for: AbstractEnumMsType
	/**
	 * Constructor for enum type applier, for transforming a enum into a
	 * Ghidra DataType.
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working.
	 */
	public EnumTypeApplier(DefaultPdbApplicator applicator) {
		super(applicator);
	}

	private long getMask(AbstractEnumMsType type, FixupContext fixupContext, boolean breakCycle)
			throws CancelledException, PdbException {
		switch (getLength(type, fixupContext, breakCycle)) {
			case 1:
				return 0xffL;
			case 2:
				return 0xffffL;
			case 4:
				return 0xffffffffL;
			default:
				return 0xffffffffffffffffL;
		}
	}

	private int getLength(AbstractEnumMsType type, FixupContext fixupContext, boolean breakCycle)
			throws CancelledException, PdbException {
		DataType underlyingDataType = getUnderlyingDataType(type, fixupContext, breakCycle);
		if (underlyingDataType == null) {
			return 1;
		}
		return Integer.max(underlyingDataType.getLength(), 1);
	}

	private DataType getUnderlyingDataType(AbstractEnumMsType type, FixupContext fixupContext,
			boolean breakCycle) throws CancelledException, PdbException {
		RecordNumber underlyingRecordNumber = type.getUnderlyingRecordNumber();
		return applicator.getProcessedDataType(underlyingRecordNumber, fixupContext, breakCycle);
	}

	boolean isSigned(AbstractEnumMsType type, FixupContext fixupContext, boolean breakCycle)
			throws CancelledException, PdbException {
		DataType underlyingType = getUnderlyingDataType(type, fixupContext, breakCycle);
		if (underlyingType == null) {
			return false;
		}
		if (underlyingType instanceof AbstractIntegerDataType) {
			return ((AbstractIntegerDataType) underlyingType).isSigned();
		}
		return false;
	}

	private EnumDataType createEmptyEnum(AbstractEnumMsType type, FixupContext fixupContext,
			boolean breakCycle) throws CancelledException, PdbException {

		AbstractEnumMsType defType = getDefinitionType(type);

		SymbolPath fixedPath = getFixedSymbolPath(defType);
		CategoryPath categoryPath = applicator.getCategory(fixedPath.getParent());

		EnumDataType enumDataType = new EnumDataType(categoryPath, fixedPath.getName(),
			getLength(defType, fixupContext, breakCycle), applicator.getDataTypeManager());

		return enumDataType;
	}

	@Override
	DataType apply(AbstractMsType type, FixupContext fixupContext, boolean breakCycle)
			throws PdbException, CancelledException {
		//Ghidra cannot handle fwdrefs and separate definitions for enumerates as it can for
		//  composites.  Thus, we will just try to provide the defined version now.
		Integer number = applicator.getNumber(type);
		Integer mapped = applicator.getMappedComplexType(number);
		AbstractEnumMsType definedEnum = (AbstractEnumMsType) applicator.getPdb()
				.getTypeRecord(RecordNumber.typeRecordNumber(mapped));

		DataType existingDt = applicator.getDataType(mapped);
		if (existingDt != null) {
			if (!(existingDt instanceof Enum)) {
				throw new PdbException("PDB error retrieving Enum type");
			}
			return existingDt;
		}

		EnumDataType enumDataType = createEmptyEnum(definedEnum, fixupContext, breakCycle);
		applyEnumMsType(enumDataType, definedEnum, fixupContext, breakCycle);

		DataType dataType = applicator.resolve(enumDataType);
		applicator.putDataType(mapped, dataType);
		return dataType;
	}

	private EnumDataType applyEnumMsType(EnumDataType enumDataType, AbstractEnumMsType type,
			FixupContext fixupContext, boolean breakCycle) throws PdbException, CancelledException {

		if (enumDataType.getCount() != 0) {
			//already applied
			return enumDataType;
		}

		String fullPathName = type.getName();

		RecordNumber fieldListRecordNumber = type.getFieldDescriptorListRecordNumber();
		FieldListTypeApplier fieldListApplier =
			FieldListTypeApplier.getFieldListApplierSpecial(applicator, fieldListRecordNumber);

		FieldListTypeApplier.FieldLists lists =
			fieldListApplier.getFieldLists(fieldListRecordNumber);

		// Note: not doing anything with getNamespaceList() or getMethodsList() at this time.
		List<AbstractEnumerateMsType> enumerates = lists.enumerates();

		int numElements = type.getNumElements();
		if (enumerates.size() != numElements) {
			pdbLogAndInfoMessage(this, "Enum expecting " + numElements + " elements, but only " +
				enumerates.size() + " available for " + fullPathName);
		}

		int length = getLength(type, fixupContext, breakCycle);
		boolean isSigned = isSigned(type, fixupContext, breakCycle);
		for (AbstractEnumerateMsType enumerateType : enumerates) {
			SymbolPath memberSymbolPath = new SymbolPath(enumerateType.getName());
			enumDataType.add(memberSymbolPath.getName(), narrowingConversion(type, length, isSigned,
				enumerateType.getNumeric(), fixupContext, breakCycle));
		}
		return enumDataType;
	}

	private long narrowingConversion(AbstractEnumMsType type, int outputSize, boolean outputSigned,
			Numeric numeric, FixupContext fixupContext, boolean breakCycle)
			throws CancelledException, PdbException {
		if (!numeric.isIntegral()) {
			Msg.info(this, "Non-integral numeric found: " + numeric);
			return 0;
		}
		if (!numeric.isIntegral()) {
			pdbLogAndInfoMessage(this, "Using zero in place of non-integral enumerate: " + numeric);
			return 0L; //
		}
		return numeric.getIntegral().longValue() & getMask(type, fixupContext, breakCycle);
	}

	private AbstractEnumMsType getDefinitionType(AbstractComplexMsType type) {
		return getDefinitionType(type, AbstractEnumMsType.class);
	}

}
