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

import ghidra.app.util.SymbolPath;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMemberFunctionMsType;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.CallingConvention;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractMemberFunctionMsType} types.
 */
public class MemberFunctionTypeApplier extends AbstractFunctionTypeApplier {

	private MsTypeApplier thisPointerApplier = null;

	/**
	 * Constructor for the applicator that applies {@link AbstractMemberFunctionMsType},
	 * transforming it into a Ghidra {@link DataType}.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractMemberFunctionMsType} to processes.
	 * @throws IllegalArgumentException Upon type mismatch.
	 */
	public MemberFunctionTypeApplier(PdbApplicator applicator, AbstractMemberFunctionMsType msType)
			throws IllegalArgumentException {
		super(applicator, msType);
	}

	@Override
	BigInteger getSize() {
		return BigInteger.ZERO;
	}

	@Override
	protected CallingConvention getCallingConvention() {
		return ((AbstractMemberFunctionMsType) msType).getCallingConvention();
	}

	@Override
	protected boolean hasThisPointer() {
		MsTypeApplier applier = applicator.getTypeApplier(
			((AbstractMemberFunctionMsType) msType).getThisPointerRecordNumber());
		if ((applier instanceof PrimitiveTypeApplier &&
			((PrimitiveTypeApplier) applier).isNoType())) {
			return false; // such as for static member functions
		}
		return true;
	}

	@Override
	protected RecordNumber getReturnRecordNumber() {
		return ((AbstractMemberFunctionMsType) msType).getReturnRecordNumber();
	}

	@Override
	protected RecordNumber getArgListRecordNumber() {
		return ((AbstractMemberFunctionMsType) msType).getArgListRecordNumber();
	}

	@Override
	protected boolean isConstructor() {
		return ((AbstractMemberFunctionMsType) msType).isConstructor();
	}

	@Override
	void apply() throws PdbException, CancelledException {
		predefineClasses();
		applyFunction(getCallingConvention(), hasThisPointer());
	}

	private void predefineClasses() throws CancelledException, PdbException {
		AbstractMemberFunctionMsType procType = (AbstractMemberFunctionMsType) msType;
		if (hasThisPointer()) {
			thisPointerApplier = getThisPointerApplier(procType);
			applicator.getPdbApplicatorMetrics().witnessMemberFunctionThisPointer(
				thisPointerApplier);
			if (thisPointerApplier instanceof PointerTypeApplier) {
				MsTypeApplier underlyingApplier =
					getThisUnderlyingApplier((PointerTypeApplier) thisPointerApplier);
				applicator.getPdbApplicatorMetrics().witnessMemberFunctionThisPointerUnderlyingType(
					underlyingApplier);
				if (underlyingApplier instanceof CompositeTypeApplier) {
					predefineClass((CompositeTypeApplier) underlyingApplier);
				}
			}
		}

		AbstractComplexTypeApplier containingApplier = getContainingComplexApplier(procType);
		applicator.getPdbApplicatorMetrics().witnessMemberFunctionContainingType(containingApplier);
		if (containingApplier instanceof CompositeTypeApplier) {
			// Do nothing at this time if Enum or something else
			predefineClass((CompositeTypeApplier) containingApplier);
		}
	}

	private void predefineClass(CompositeTypeApplier applier) {
		SymbolPath containingClassSymbolPath = applier.getFixedSymbolPath();
		applicator.predefineClass(containingClassSymbolPath);
	}

//	private AbstractPointerMsType getThisType(AbstractMemberFunctionMsType procType)
//			throws CancelledException, PdbException {
//		int thisPointerTypeIndex = procType.getThisPointerTypeIndex();
//		AbstractMsTypeApplier applier = applicator.getTypeApplier(thisPointerTypeIndex);
//
//		if ((applier instanceof PrimitiveTypeApplier &&
//			((PrimitiveTypeApplier) applier).isNoType())) {
//			return null; // such as for static member functions
//		}
//		if (!(applier instanceof PointerTypeApplier)) {
//			applicator.getLog().appendMsg("thisApplier is invalid type for " + msType.getName());
//			return null;
//		}
//		AbstractMsType thisMsType = applier.getMsType();
//		// shouldn't need to do this next test, as an applier should only get this type
//		if (!(thisMsType instanceof AbstractPointerMsType)) {
//			applicator.getLog().appendMsg("thisMsType is invalid type for " + msType.getName());
//			return null;
//		}
//		return (AbstractPointerMsType) thisMsType;
//
//	}
//
//	private void processContainingClass(AbstractMemberFunctionMsType procType)
//			throws CancelledException, PdbException {
//		int containingClassTypeIndex = procType.getContainingClassTypeIndex();
//
//		CompositeTypeApplier containingCompositeApplier =
//			applicator.getCompositeApplier(containingClassTypeIndex);
////
////		ApplyCompositeType containingCompositeApplier =
////			(ApplyCompositeType) applicator.getExpectedTypeApplier(containingClassTypeIndex,
////				ApplyCompositeType.class);
//
////		AbstractApplyMsType containingTypeApplier =
////			applicator.getTypeApplier(containingClassTypeIndex, false);
////		if (containingTypeApplier == null) {
////			applicator.getLog().appendMsg(
////				"containingClassApplier is null for " + msType.getName());
////			return null;
////		}
////		if (!(containingTypeApplier instanceof ApplyCompositeType)) {
////			applicator.getLog().appendMsg(
////				"containingClassApplier is invalid type for " + msType.getName());
////			return null;
////		}
////		ApplyCompositeType containingCompositeApplier = (ApplyCompositeType) containingTypeApplier;
//		SymbolPath containingClassSymbolPath = containingCompositeApplier.getFixedSymbolPath();
//		applicator.predefineClass(containingClassSymbolPath);
//
//	}

//	private boolean hasThisPointer(AbstractMemberFunctionMsType procType)
//			throws CancelledException, PdbException {
//		int thisPointerTypeIndex = procType.getThisPointerTypeIndex();
//		AbstractMsTypeApplier applier = applicator.getTypeApplier(thisPointerTypeIndex);
//		if ((applier instanceof PrimitiveTypeApplier &&
//			((PrimitiveTypeApplier) applier).isNoType())) {
//			return false; // such as for static member functions
//		}
//		return true;
//	}

	private MsTypeApplier getThisPointerApplier(AbstractMemberFunctionMsType procType) {
		MsTypeApplier applier = applicator.getTypeApplier(procType.getThisPointerRecordNumber());

//		if ((applier instanceof PrimitiveTypeApplier &&
//		((PrimitiveTypeApplier) applier).isNoType())) {
//		return null; // such as for static member functions
//	}
//	// Cannot just check of PointerTypeApplier because could instead be a
//	// PrimitiveTypeApplier with PointerDataType as dataType
//	if (!(applier.getDataType() instanceof PointerDataType)) {
//		applicator.appendLogMsg(applier.getMsType().getClass().getSimpleName() +
//			" this type is invalid type for " + msType.getClass().getSimpleName());
//		return null;
//	}
		applicator.addApplierDependency(this, applier);
		return applier;
	}

	private MsTypeApplier getThisUnderlyingApplier(PointerTypeApplier thisApplier) {
		return thisApplier.getUnmodifiedUnderlyingTypeApplier();
	}

	private AbstractComplexTypeApplier getContainingComplexApplier(
			AbstractMemberFunctionMsType procType) throws PdbException {
		return AbstractComplexTypeApplier.getComplexApplier(applicator,
			procType.getContainingClassRecordNumber());
	}

//	private void processPointerUnderlyingType()
//			throws CancelledException, PdbException {
//
//		AbstractMsTypeApplier thisUnderlyingTypeApplier = thisPointerApplier.getUnmodifiedUnderlyingTypeApplier();
//
//		if (!(thisUnderlyingTypeApplier instanceof CompositeTypeApplier)) {
//			applicator.getLog().appendMsg(
//				"thisUnderlyingTypeApplier is invalid type for " + msType.getName());
//			return;
//		}
//		CompositeTypeApplier thisUnderlyingCompositeApplier =
//			(CompositeTypeApplier) thisUnderlyingTypeApplier;
//		SymbolPath thisUnderlyingClassSymbolPath =
//			thisUnderlyingCompositeApplier.getFixedSymbolPath();
//		applicator.predefineClass(thisUnderlyingClassSymbolPath);
//	}

//	private AbstractPointerMsType processThisPointer(AbstractMemberFunctionMsType procType)
//			throws CancelledException, PdbException {
//		int thisPointerTypeIndex = procType.getThisPointerTypeIndex();
//		AbstractMsTypeApplier thisPointerApplier = applicator.getTypeApplier(thisPointerTypeIndex);
//
//		if ((thisPointerApplier instanceof PrimitiveTypeApplier &&
//			((PrimitiveTypeApplier) thisPointerApplier).isNoType())) {
//			return null; // such as for static member functions
//		}
//		if (!(thisPointerApplier instanceof PointerTypeApplier)) {
//			applicator.getLog().appendMsg("thisApplier is invalid type for " + msType.getName());
//			return null;
//		}
//		return (AbstractPointerMsType) thisPointerApplier.getMsType();
//	}
//
//	private void processPointerUnderlyingType(AbstractPointerMsType thisPointerMsType)
//			throws CancelledException, PdbException {
//
//		int thisUnderlyingTypeIndex = thisPointerMsType.getUnderlyingTypeIndex();
//		AbstractMsTypeApplier thisUnderlyingTypeApplier =
//			applicator.getTypeApplier(thisUnderlyingTypeIndex);
//
//		// TODO: does not recurse below one level of modifiers... consider doing a recursion.
//		if (thisUnderlyingTypeApplier instanceof ModifierTypeApplier) {
//			ModifierTypeApplier x = (ModifierTypeApplier) thisUnderlyingTypeApplier;
//			int y = ((AbstractModifierMsType) (x.getMsType())).getModifiedTypeIndex();
//			thisUnderlyingTypeApplier = applicator.getTypeApplier(y);
//		}
//		if (!(thisUnderlyingTypeApplier instanceof CompositeTypeApplier)) {
//			applicator.getLog().appendMsg(
//				"thisUnderlyingTypeApplier is invalid type for " + msType.getName());
//			return;
//		}
//		CompositeTypeApplier thisUnderlyingCompositeApplier =
//			(CompositeTypeApplier) thisUnderlyingTypeApplier;
//		SymbolPath thisUnderlyingClassSymbolPath =
//			thisUnderlyingCompositeApplier.getFixedSymbolPath();
//		applicator.predefineClass(thisUnderlyingClassSymbolPath);
//	}
}
