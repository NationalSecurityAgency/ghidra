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
import ghidra.program.model.data.*;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractMemberFunctionMsType} types.
 */
public class MemberFunctionTypeApplier extends AbstractFunctionTypeApplier {

	// Intended for: AbstractMemberFunctionMsType
	/**
	 * Constructor for the applicator that applies {@link AbstractMemberFunctionMsType},
	 * transforming it into a Ghidra {@link DataType}.
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working.
	 * @throws IllegalArgumentException Upon type mismatch.
	 */
	public MemberFunctionTypeApplier(DefaultPdbApplicator applicator)
			throws IllegalArgumentException {
		super(applicator);
	}

	private MsTypeApplier getThisPointerApplier(AbstractMemberFunctionMsType procType) {
		MsTypeApplier applier = applicator.getTypeApplier(procType.getThisPointerRecordNumber());
		return applier;
	}

	@Override
	protected CallingConvention getCallingConvention(AbstractMsType type) {
		return ((AbstractMemberFunctionMsType) type).getCallingConvention();
	}

	@Override
	protected Pointer getThisPointer(AbstractMsType type, FixupContext fixupContext,
			boolean breakCycle) throws CancelledException, PdbException {
		RecordNumber ptrRecord = ((AbstractMemberFunctionMsType) type).getThisPointerRecordNumber();
		if (ptrRecord == null) {
			return null;
		}
		AbstractMsType mType = applicator.getPdb().getTypeRecord(ptrRecord);
		if (mType instanceof PrimitiveMsType primitive && primitive.isNoType()) {
			return null;
		}
		if (mType instanceof AbstractPointerMsType msPtr) {
			predefineClass(msPtr.getUnderlyingRecordNumber());
		}
		applicator.getPdbApplicatorMetrics().witnessMemberFunctionThisPointer(mType);
		DataType dt = applicator.getProcessedDataType(ptrRecord, fixupContext, breakCycle);
		if (dt instanceof Pointer ptr) {
			return ptr;
		}
		return null;
	}

	@Override
	protected Composite getContainingComplexApplier(AbstractMsType type, FixupContext fixupContext,
			boolean breakCycle) throws CancelledException, PdbException {
		RecordNumber containerRecord =
			((AbstractMemberFunctionMsType) type).getContainingClassRecordNumber();
		if (containerRecord == null) {
			return null;
		}
		AbstractMsType mType = applicator.getPdb().getTypeRecord(containerRecord);
		applicator.getPdbApplicatorMetrics().witnessMemberFunctionContainingType(mType);
		DataType dt = applicator.getProcessedDataType(containerRecord, fixupContext, breakCycle);
		if (dt instanceof Composite composite) {
			return composite;
		}
		return null;
	}

	@Override
	protected void processContainingType(AbstractMsType type) {
		RecordNumber containerRecord =
			((AbstractMemberFunctionMsType) type).getContainingClassRecordNumber();
		if (containerRecord == null) {
			return;
		}
		predefineClass(containerRecord);
		AbstractMsType mType = applicator.getPdb().getTypeRecord(containerRecord);
		applicator.getPdbApplicatorMetrics().witnessMemberFunctionContainingType(mType);
	}

	private void predefineClass(RecordNumber recordNumber) {
		AbstractMsType type = applicator.getPdb().getTypeRecord(recordNumber);
		if (!(type instanceof AbstractCompositeMsType msComposite)) {
			return;
		}
		MsTypeApplier applier = applicator.getTypeApplier(recordNumber);
		if (!(applier instanceof CompositeTypeApplier compApplier)) {
			return;
		}
		SymbolPath sp = compApplier.getFixedSymbolPath(msComposite);
		applicator.predefineClass(sp);
	}

	@Override
	protected boolean isConstructor(AbstractMsType type) {
		return ((AbstractMemberFunctionMsType) type).isConstructor();
	}

	@Override
	protected RecordNumber getReturnRecordNumber(AbstractMsType type) {
		return ((AbstractMemberFunctionMsType) type).getReturnRecordNumber();
	}

	@Override
	protected RecordNumber getArgListRecordNumber(AbstractMsType type) {
		return ((AbstractMemberFunctionMsType) type).getArgListRecordNumber();
	}

}
