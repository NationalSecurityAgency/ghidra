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

import ghidra.app.util.SymbolPath;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractPointerMsType.MsPointerMode;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractPointerMsType} types.
 */
public class PointerTypeApplier extends MsDataTypeApplier {

	// Intended for: AbstractPointerMsType
	/**
	 * Constructor for pointer type applier, for transforming a enum into a Ghidra DataType
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working
	 * @throws IllegalArgumentException Upon invalid arguments
	 */
	public PointerTypeApplier(DefaultPdbApplicator applicator) throws IllegalArgumentException {
		super(applicator);
	}

	/**
	 * Comment field if this type is used as a structure member.  This method could go away later
	 *  if we develop member pointers into the Ghidra framework; this method exists to pass some
	 *  pertinent information along to the user
	 * @param type the PDB type being inspected
	 * @return comment string or null
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon processing error
	 */
	String getPointerCommentField(AbstractPointerMsType type)
			throws CancelledException, PdbException {
		AbstractPointerMsType.MsPointerMode msPointerMode = type.getPointerMode();
		if (msPointerMode == AbstractPointerMsType.MsPointerMode.MEMBER_FUNCTION_POINTER) {
			// We are no longer able to get underlying type in time due to cycle breaks unless
			// we start doing fixups on pmf/pdm pointers.
			// TODO: consider fixups on these later... maybe after we understand contents of
			// pmf/pdm and evaluate whether there is another way of passing this information to
			// the user.
			//DataType underlyingType = getUnderlyingType(type, fixupContext);
			//return "\"::*\" (pmf) to type: " + underlyingType;
			return "\"::*\" (pmf)";
		}
		else if (msPointerMode == AbstractPointerMsType.MsPointerMode.MEMBER_DATA_POINTER) {
			// We are no longer able to get underlying type in time due to cycle breaks unless
			// we start doing fixups on pmf/pdm pointers.
			// TODO: consider fixups on these later... maybe after we understand contents of
			// pmf/pdm and evaluate whether there is another way of passing this information to
			// the user.
			//DataType underlyingType = getUnderlyingType(type, fixupContext);
			//return "\"::*\" (pdm) to type: " + underlyingType;
			return "\"::*\" (pdm)";
		}
		return null;
	}

	@Override
	boolean apply(AbstractMsType type) throws PdbException, CancelledException {

		AbstractPointerMsType pointerMsType = (AbstractPointerMsType) type;
		// Doing pre-check on type first using the getDataTypeOrSchedule method.  The logic is
		//  simpler here for Composites or Functions because we only have one dependency type,
		//  so we are not doing a separate call to a pre-check method as there is in those appliers.
		//  If type is not available, return false.
		RecordNumber underlyingRecordNumber = pointerMsType.getUnderlyingRecordNumber();
		DataType underlyingType = applicator.getDataTypeOrSchedule(underlyingRecordNumber);
		if (underlyingType == null) {
			return false;
		}

		DataType dataType;

		if (type instanceof DummyMsType) {
			dataType = new PointerDataType(applicator.getDataTypeManager());
		}
		else {
			AbstractPointerMsType.MsPointerMode msPointerMode = pointerMsType.getPointerMode();
			switch (msPointerMode) {
				case POINTER:
					dataType = processPointer(pointerMsType, underlyingType);
					break;
				case LVALUE_REFERENCE:
					dataType = processReference(pointerMsType, underlyingType);
					break;
				case RVALUE_REFERENCE:
					dataType = processReference(pointerMsType, underlyingType);
					break;
				case MEMBER_DATA_POINTER:
				case MEMBER_FUNCTION_POINTER:
					dataType = processMemberPointer(pointerMsType, underlyingType);
					break;
				case INVALID:
				case RESERVED:
					Msg.warn(this, "Unable to process PointerMode: " + msPointerMode +
						". Using default Pointer.");
					dataType = PointerDataType.dataType;
					break;
				default:
					throw new PdbException("PDB Error: unhandled PointerMode in " + getClass());
			}
		}

		applicator.putDataType(type, dataType);
		return true;
	}

	private DataType processMemberPointer(AbstractPointerMsType type, DataType underlyingType) {

		int size = type.getSize().intValueExact();

		String name;
		AbstractPointerMsType.MsPointerMode msPointerMode = type.getPointerMode();
		if (msPointerMode == AbstractPointerMsType.MsPointerMode.MEMBER_FUNCTION_POINTER) {
			name = String.format("pmf_%08x", type.toString().hashCode());
		}
		else {
			name = String.format("pdm_%08x", type.toString().hashCode());
		}

		RecordNumber containingClassRecordNumber =
			type.getMemberPointerContainingClassRecordNumber();
		CategoryPath storagePath = getCategoryPathForMemberPointer(containingClassRecordNumber);
		DataType dt = new StructureDataType(storagePath, name, size);
		dt.setDescription(type.toString());

		return dt;
	}

	private CategoryPath getCategoryPathForMemberPointer(RecordNumber containingClassRecordNumber) {
		if (containingClassRecordNumber != null) {
			AbstractMsType containingType = applicator.getTypeRecord(containingClassRecordNumber);
			MsTypeApplier applier = applicator.getTypeApplier(containingClassRecordNumber);
			if (containingType instanceof AbstractCompositeMsType compositeMsType &&
				applier instanceof CompositeTypeApplier compositeApplier) {
				SymbolPath symbolPath = compositeApplier.getFixedSymbolPath(compositeMsType);
				CategoryPath categoryPath = applicator.getCategory(symbolPath);
				return ClassTypeUtils.getInternalsCategoryPath(categoryPath);
			}
		}
		return applicator.getAnonymousTypesCategory();
	}

	private DataType processPointer(AbstractPointerMsType type, DataType underlyingType) {
		int size = type.getSize().intValueExact();
		if (size > PointerDataType.MAX_POINTER_SIZE_BYTES) {
			return getStubPointer(type);
		}
		if (size == applicator.getDataOrganization().getPointerSize()) {
			size = -1; // Use default
		}
		return new PointerDataType(underlyingType, size, applicator.getDataTypeManager());
	}

	private DataType processReference(AbstractPointerMsType type, DataType underlyingType) {
		int size = type.getSize().intValueExact();
		if (size > PointerDataType.MAX_POINTER_SIZE_BYTES) {
			return getStubPointer(type);
		}
		if (size == applicator.getDataOrganization().getPointerSize()) {
			size = -1; // Use default
		}
		return new PointerDataType(underlyingType, size, applicator.getDataTypeManager());
	}

	private DataType getStubPointer(AbstractPointerMsType type) {
		int size = type.getSize().intValueExact();
		AbstractMsType under = applicator.getTypeRecord(type.getUnderlyingRecordNumber());
		CategoryPath categoryPath = applicator.getAnonymousTypesCategory();
		MsPointerMode msPointerMode = type.getPointerMode();
		AbstractPointerMsType.PointerType pt = type.getPointerType();
		String name = String.format("StubPtr%d_%s%s_To_%s", 8 * size, pt.toString(),
			msPointerMode.toString(), under.getName());
		DataType stubPtr = new StructureDataType(categoryPath, name, size);
		return stubPtr;
	}

//	private DataType processMemberPointerFuture(AbstractPointerMsType type) {
//		TODO: Incorporate some of processMemberPointer()
//		AbstractPointerMsType.MemberPointerType memberPointerType = type.getMemberPointerType();
//
//		int a = 1;
//		Msg.info(this, String.format("size: %d mpt: %s", size, memberPointerType));
//
//		switch (memberPointerType) {
//			case INVALID:
//				a = a + 1;
//				break;
//			case UNSPECIFIED:
//				a = a + 1;
//				break;
//			case DATA_SINGLE_INHERITANCE:
//				a = a + 1;
//				break;
//			case DATA_MULTIPLE_INHERITANCE:
//				a = a + 1;
//				break;
//			case DATA_VIRTUAL_INHERITANCE:
//				a = a + 1;
//				break;
//			case DATA_GENERAL:
//				a = a + 1;
//				break;
//			case FUNCTION_SINGLE_INHERITANCE:
//				a = a + 1;
//				break;
//			case FUNCTION_MULTIPLE_INHERITANCE:
//				a = a + 1;
//				// temporary code in place of more permanent code, but need something to help analyze
//				// how this member of a class/structure is being used.
////				if (size == 16) {
////					return pmfDummy;
////				}
//				break;
//			case FUNCTION_VIRTUAL_INHERITANCE:
//				a = a + 1;
//				break;
//			case FUNCTION_SINGLE_INHERITANCE_1632:
//				a = a + 1;
//				break;
//			case FUNCTION_MULTIPLE_INHERITANCE_1632:
//				a = a + 1;
//				break;
//			case FUNCTION_VIRTUAL_INHERITANCE_1632:
//				a = a + 1;
//				break;
//			case FUNCTION_SINGLE_INHERITANCE_32:
//				a = a + 1;
//				break;
//			case FUNCTION_MULTIPLE_INHERITANCE_32:
//				a = a + 1;
//				break;
//			case FUNCTION_VIRTUAL_INHERITANCE_32:
//				a = a + 1;
//				break;
//			default:
//				a = a + 1;
//				break;
//		}
//		return null;
//	}
//
//	private DataType processPointerFuture(AbstractPointerMsType type) {
//		//
//		AbstractPointerMsType.PointerType pointerType = type.getPointerType();
//		//Msg.info(this, String.format("size: %d pt: %s", size, pointerType));
//		int a = 1;
//		switch (pointerType) {
//			case INVALID:
//				a = a + 1;
//				break;
//			case NEAR:
//				a = a + 1;
//				break;
//			case FAR:
//				a = a + 1;
//				break;
//			case HUGE:
//				a = a + 1;
//				break;
//			case SEGMENT_BASED:
//				a = a + 1;
//				break;
//			case VALUE_BASED:
//				a = a + 1;
//				break;
//			case SEGMENT_VALUE_BASED:
//				a = a + 1;
//				break;
//			case ADDRESS_BASED:
//				a = a + 1;
//				break;
//			case SEGMENT_ADDRESS_BASED:
//				a = a + 1;
//				break;
//			case TYPE_BASED:
//				a = a + 1;
//				break;
//			case SELF_BASED:
//				a = a + 1;
//				break;
//			case NEAR32:
//				a = a + 1;
//				break;
//			case FAR32:
//				a = a + 1;
//				break;
//			case PTR64:
//				a = a + 1;
//				break;
//			case UNSPECIFIED:
//				a = a + 1;
//				break;
//			default:
//				a = a + 1;
//				break;
//		}
//		return null;
//	}

}
