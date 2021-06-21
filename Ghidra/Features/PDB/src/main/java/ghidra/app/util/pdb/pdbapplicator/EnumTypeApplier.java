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
import java.util.List;

import ghidra.app.util.SymbolPath;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractEnumMsType;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.MsProperty;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractEnumMsType} types.
 */
public class EnumTypeApplier extends AbstractComplexTypeApplier {

	//private AbstractMsTypeApplier underlyingApplier = null;

//	private int length = 0;
//	private boolean isSigned = false;
//

	/**
	 * Constructor for enum type applier, for transforming a enum into a
	 * Ghidra DataType.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractEnumMsType} to process.
	 */
	public EnumTypeApplier(PdbApplicator applicator, AbstractEnumMsType msType) {
		super(applicator, msType);
	}

	@Override
	BigInteger getSize() {
		MsTypeApplier underlyingApplier = getUnderlyingTypeApplier();
		if (underlyingApplier == null) {
			return BigInteger.ZERO;
		}
		return underlyingApplier.getSize();
	}

	private long getMask() {
		switch (getLength()) {
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

	private int getLength() {
		// Minimum length allowed by Ghidra is 1 for enum, so all returns are min 1.
		MsTypeApplier underlyingApplier = getUnderlyingTypeApplier();
		if (underlyingApplier == null) {
			return 1;
		}
		DataType underlyingType = underlyingApplier.getDataType();
		if (underlyingType == null) {
			return 1;
		}
		return Integer.max(underlyingType.getLength(), 1);
	}

	boolean isSigned() {
		MsTypeApplier underlyingApplier = getUnderlyingTypeApplier();
		if (underlyingApplier == null) {
			return false;
		}
		DataType underlyingType = underlyingApplier.getDataType();
		if (underlyingType == null) {
			return false;
		}
		if (underlyingType instanceof AbstractIntegerDataType) {
			return ((AbstractIntegerDataType) underlyingType).isSigned();
		}
		return false;
	}

	@Override
	EnumTypeApplier getDependencyApplier() {
		if (definitionApplier != null && definitionApplier instanceof EnumTypeApplier) {
			return (EnumTypeApplier) definitionApplier;
		}
		return this;
	}

	String getName() {
		return getMsType().getName();
	}

	private MsTypeApplier getUnderlyingTypeApplier() {
		MsTypeApplier under = null;
		MsTypeApplier applier = (definitionApplier != null) ? definitionApplier : this;
		RecordNumber underlyingRecordNumber =
			((AbstractEnumMsType) applier.getMsType()).getUnderlyingRecordNumber();
		under = applicator.getTypeApplier(underlyingRecordNumber);
		if (under == null) {
			applicator.appendLogMsg("Missing applier for underlying type index " +
				underlyingRecordNumber + " in Enum " + msType.getName());
		}
		return under;
	}

	private EnumDataType createEmptyEnum(AbstractEnumMsType type) {

		SymbolPath fixedPath = getFixedSymbolPath();
		CategoryPath categoryPath = applicator.getCategory(fixedPath.getParent());

//		MsProperty property = type.getMsProperty();
//		if (property.isForwardReference()) {
//			// investigate this
//		}
////		RecordNumber underlyingRecordNumber = type.getUnderlyingRecordNumber();
////		underlyingApplier = applicator.getApplier(underlyingRecordNumber);
//		determineUnderlyingTypeApplier();
//
//		if (underlyingApplier == null) {
//			return null;
//		}
//		DataType underlyingType = underlyingApplier.getDataType();
//		if (underlyingType != null) {
//			length = underlyingType.getLength();
//			if (underlyingType instanceof AbstractIntegerDataType) {
//				isSigned = ((AbstractIntegerDataType) underlyingType).isSigned();
//			}
//			else if (!(underlyingType instanceof VoidDataType)) {
//			pdbLogAndInfoMessage(this, "Cannot processes enum with underlying type: " +
//					underlyingType.getClass().getSimpleName());
//				throw new PdbException(msg);
//			}
//		}
//		else {
//			AbstractMsType underlying = underlyingApplier.getMsType();
//			if (underlying instanceof PrimitiveMsType) {
//				length = ((PrimitiveMsType) underlying).getTypeSize();
//				//TODO: can we set isSigned in here?  ((PrimitiveMsType) underlying)
//				// TODO: there might be more
//				// TODO: investigate getSize() on AbstractMsType?
//				//       then: length = underlying.getSize();
//			}
//		}
//		// Ghidra does not like size of zero.
//		length = Integer.max(length, 1);

		EnumDataType enumDataType = new EnumDataType(categoryPath, fixedPath.getName(), getLength(),
			applicator.getDataTypeManager());

		return enumDataType;
	}

	@Override
	void apply() throws PdbException, CancelledException {
		getOrCreateEnum();

		AbstractEnumMsType type = (AbstractEnumMsType) msType;
		MsProperty property = type.getMsProperty();
		if (property.isForwardReference()) {
			return;
		}

		applyEnumMsType((AbstractEnumMsType) msType);

	}

	@Override
	void resolve() {
		if (!isForwardReference()) {
			super.resolve();
		}
	}

	// Mapping of fwdRef/def must be done prior to this call.
	private void getOrCreateEnum() {
		AbstractEnumMsType neededType = (AbstractEnumMsType) msType;
		if (dataType != null) {
			return;
		}
		if (isForwardReference()) {
			if (definitionApplier != null) {
				dataType = definitionApplier.getDataTypeInternal();
				if (dataType != null) {
					return;
				}
				neededType = (AbstractEnumMsType) definitionApplier.getMsType();
			}
		}
		else {
			if (forwardReferenceApplier != null) {
				dataType = forwardReferenceApplier.getDataTypeInternal();
				if (dataType != null) {
					return;
				}
			}
		}
		dataType = createEmptyEnum(neededType);
	}

	private EnumDataType applyEnumMsType(AbstractEnumMsType type) throws PdbException {

		String fullPathName = type.getName();

//		// TODO: evaluate whether we do full SymbolPath... see others
//		SymbolPath fixedPath = getFixedSymbolPath();
//
//		RecordNumber underlyingRecordNumber = type.getUnderlyingRecordNumber();
//		MsProperty property = type.getMsProperty();
//		if (property.isForwardReference()) {
//			// investigate this
//		}
//		underlyingApplier = applicator.getApplier(underlyingRecordNumber);
//
//		if (underlyingApplier == null) {
//			applicator.appendLogMsg("Missing applier for underlying type index " +
//				underlyingRecordNumber + " in Enum " + fullPathName);
//			return null;
//		}
//		DataType underlyingType = underlyingApplier.getDataType();
//		int length = 0;
//		if (underlyingType != null) {
//			length = underlyingType.getLength();
//		}
//		else {
//			AbstractMsType underlying = underlyingApplier.getMsType();
//			if (underlying instanceof PrimitiveMsType) {
//				length = ((PrimitiveMsType) underlying).getTypeSize();
//				// TODO: there might be more
//				// TODO: investigate getSize() on AbstractMsType?
//				//       then: length = underlying.getSize();
//			}
//		}
//		// Ghidra does not like size of zero.
//		length = Integer.max(length, 1);
//
//		CategoryPath categoryPath = applicator.getCategory(fixedPath.getParent());
//		EnumDataType enumDataType = new EnumDataType(categoryPath, fixedPath.getName(), length,
//			applicator.getDataTypeManager());
//

		RecordNumber fieldListRecordNumber = type.getFieldDescriptorListRecordNumber();
		FieldListTypeApplier fieldListApplier =
			FieldListTypeApplier.getFieldListApplierSpecial(applicator, fieldListRecordNumber);

		// Note: not doing anything with getNamespaceList() or getMethodsList() at this time.
		List<MsTypeApplier> memberList = fieldListApplier.getMemberList();

		int numElements = type.getNumElements();
		if (memberList.size() != numElements) {
			pdbLogAndInfoMessage(this, "Enum expecting " + numElements + " elements, but only " +
				memberList.size() + " available for " + fullPathName);
		}
		EnumDataType enumDataType = (EnumDataType) dataType;
		int length = getLength();
		boolean isSigned = isSigned();
		for (MsTypeApplier memberApplier : memberList) {
			if (memberApplier instanceof EnumerateTypeApplier) {
				EnumerateTypeApplier enumerateApplier = (EnumerateTypeApplier) memberApplier;
				SymbolPath memberSymbolPath = new SymbolPath(enumerateApplier.getName());
				enumDataType.add(memberSymbolPath.getName(),
					narrowingConversion(length, isSigned, enumerateApplier.getNumeric()));
			}
			else { // (member instanceof AbstractMemberMsType)
					// I do not believe (until proven otherwise) that an Enum will have members of
					//  type AbstractMemberMsType.
				pdbLogAndInfoMessage(this, getClass().getSimpleName() + ": unexpected " +
					memberApplier.getClass().getSimpleName());
			}
		}
		return enumDataType;
	}

	private long narrowingConversion(int outputSize, boolean outputSigned, Numeric numeric) {
		if (!numeric.isIntegral()) {
			Msg.info(this, "Non-integral numeric found: " + numeric);
			return 0;
		}
		if (!numeric.isIntegral()) {
			pdbLogAndInfoMessage(this, "Using zero in place of non-integral enumerate: " + numeric);
			return 0L; //
		}
		return numeric.getIntegral().longValue() & getMask();
//		return NarrowingConverter.narrowBigToLong(outputSize, outputSigned, numeric.getSize(),
//			numeric.isSigned(), numeric.getIntegral());
	}

}
