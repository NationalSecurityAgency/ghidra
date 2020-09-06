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
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractProcedureMsType;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.CallingConvention;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractProcedureMsType} types.
 */
public class ProcedureTypeApplier extends AbstractFunctionTypeApplier {

	/**
	 * Constructor for the applicator that applies {@link AbstractProcedureMsType},
	 * transforming it into a Ghidra {@link DataType}.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractProcedureMsType} to processes.
	 * @throws IllegalArgumentException Upon invalid arguments.
	 */
	public ProcedureTypeApplier(PdbApplicator applicator, AbstractProcedureMsType msType)
			throws IllegalArgumentException {
		super(applicator, msType);
	}

	@Override
	BigInteger getSize() {
		return BigInteger.ZERO;
	}

	@Override
	protected CallingConvention getCallingConvention() {
		return ((AbstractProcedureMsType) msType).getCallingConvention();
	}

	@Override
	protected boolean hasThisPointer() {
		return false;
	}

	@Override
	protected RecordNumber getReturnRecordNumber() {
		return ((AbstractProcedureMsType) msType).getReturnRecordNumber();
	}

	@Override
	protected RecordNumber getArgListRecordNumber() {
		return ((AbstractProcedureMsType) msType).getArgListRecordNumber();
	}

	@Override
	void apply() throws PdbException, CancelledException {
		applyFunction(getCallingConvention(), hasThisPointer());

//		AbstractProcedureMsType procType = (AbstractProcedureMsType) msType;
//		applyFunction(procType.getCallingConvention(), false, procType.getReturnTypeIndex(),
//			procType.getArgListTypeIndex());
//		DataType definition = applyFunction(procType.getCallingConvention(), false,
//			procType.getReturnTypeIndex(), procType.getArgListTypeIndex());
//		ghDataTypeDB = applicator.resolve(definition);
	}

}
