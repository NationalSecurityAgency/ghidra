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
import ghidra.program.model.data.*;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractPointerMsType} types.
 */
public class PointerTypeApplier extends MsTypeApplier {

	private String memberComment = null;

	/**
	 * Constructor for pointer type applier, for transforming a enum into a
	 * Ghidra DataType.
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working.
	 * @param msType {@link AbstractPointerMsType} to process
	 * @throws IllegalArgumentException Upon invalid arguments.
	 */
	public PointerTypeApplier(DefaultPdbApplicator applicator, AbstractPointerMsType msType)
			throws IllegalArgumentException {
		super(applicator, msType);
	}

	/**
	 * Comment field if this type is used as a structure member.  This method could go away later
	 *  if we develop member pointers into the Ghidra framework; this method exists to pass some
	 *  pertinent information along to the user
	 * @return comment string or null
	 */
	String getPointerCommentField() {
		return memberComment;
	}

	@Override
	BigInteger getSize() {
		return ((AbstractPointerMsType) msType).getSize();
	}

	@Override
	void apply() throws PdbException, CancelledException {
		if (msType instanceof DummyMsType) {
			dataType = new PointerDataType(applicator.getDataTypeManager());
		}
		else {
			dataType = applyAbstractPointerMsType((AbstractPointerMsType) msType);
		}
	}

	@Override
	void resolve() {
		// Do not resolve pointer types... will be resolved naturally, as needed
	}

	MsTypeApplier getUnmodifiedUnderlyingTypeApplier() {
		MsTypeApplier thisUnderlyingTypeApplier =
			applicator.getTypeApplier(((AbstractPointerMsType) msType).getUnderlyingRecordNumber());

		// TODO: does not recurse below one level of modifiers... consider doing a recursion.
		if (thisUnderlyingTypeApplier instanceof ModifierTypeApplier) {
			ModifierTypeApplier x = (ModifierTypeApplier) thisUnderlyingTypeApplier;
			RecordNumber recNum =
				((AbstractModifierMsType) (x.getMsType())).getModifiedRecordNumber();
			thisUnderlyingTypeApplier = applicator.getTypeApplier(recNum);
		}
		return thisUnderlyingTypeApplier;
	}

	private DataType getUnderlyingType(AbstractPointerMsType type) {
		MsTypeApplier underlyingApplier =
			applicator.getTypeApplier(type.getUnderlyingRecordNumber());

		DataType underlyingType = underlyingApplier.getCycleBreakType();
		if (underlyingType == null) {
			// TODO: we have seen underlyingTypeApplier is for NoTypeApplier for VtShapeMsType
			//  Figure it out, and perhaps create an applier that creates a structure or something?
			underlyingType = applicator.getPdbPrimitiveTypeApplicator().getVoidType();
			applicator.appendLogMsg(
				"PDB Warning: No type conversion for " + underlyingApplier.getMsType().toString() +
					" as underlying type for pointer. Using void.");
		}
		return underlyingType;
	}

	private DataType applyAbstractPointerMsType(AbstractPointerMsType type) {

		AbstractPointerMsType.PointerMode pointerMode = type.getPointerMode();
		if (pointerMode == AbstractPointerMsType.PointerMode.MEMBER_DATA_POINTER ||
			pointerMode == AbstractPointerMsType.PointerMode.MEMBER_FUNCTION_POINTER) {
			return processMemberPointer(type);
		}
		return processPointer(type);
	}

	private DataType processMemberPointer(AbstractPointerMsType type) {
		DataType underlyingType = getUnderlyingType(type);
		int size = type.getSize().intValueExact();
		RecordNumber memberPointerContainingClassRecordNumber =
			type.getMemberPointerContainingClassRecordNumber();
		MsTypeApplier containingClassApplier =
			applicator.getTypeApplier(memberPointerContainingClassRecordNumber);

		DataType dt = null;
		String name;
		AbstractPointerMsType.PointerMode pointerMode = type.getPointerMode();
		if (pointerMode == AbstractPointerMsType.PointerMode.MEMBER_FUNCTION_POINTER) {
			name = String.format("pmf_%08x", type.toString().hashCode());
			memberComment = "\"::*\" (pmf) to type: " + underlyingType;
		}
		else {
			name = String.format("pdm_%08x", type.toString().hashCode());
			memberComment = "\"::*\" (pdm) to type: " + underlyingType;
		}

		if (containingClassApplier instanceof CompositeTypeApplier cta) {
			DataTypePath dtp = ClassTypeUtils.getInternalsDataTypePath(cta, name);
			if (dtp != null) {
				dt = applicator.getDataTypeManager().getDataType(dtp);
				if (dt == null) {
					dt = new StructureDataType(dtp.getCategoryPath(), dtp.getDataTypeName(), size);
					dt.setDescription(type.toString());
				}
			}
		}
		if (dt == null) {
			dt = Undefined.getUndefinedDataType(size);
		}
		return dt;
	}

	private DataType processPointer(AbstractPointerMsType type) {
		memberComment = null;
		DataType underlyingType = getUnderlyingType(type);
		int size = type.getSize().intValueExact();
		if (size == applicator.getDataOrganization().getPointerSize()) {
			size = -1; // Use default
		}
		return new PointerDataType(underlyingType, size, applicator.getDataTypeManager());
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
