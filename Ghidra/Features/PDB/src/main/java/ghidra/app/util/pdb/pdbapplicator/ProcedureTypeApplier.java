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
import ghidra.program.model.data.Pointer;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractProcedureMsType} types.
 */
public class ProcedureTypeApplier extends AbstractFunctionTypeApplier {

	// Intended for: AbstractProcedureMsType
	/**
	 * Constructor for the applicator that applies {@link AbstractProcedureMsType},
	 * transforming it into a Ghidra {@link DataType}
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working
	 * @throws IllegalArgumentException Upon invalid arguments
	 */
	public ProcedureTypeApplier(DefaultPdbApplicator applicator) throws IllegalArgumentException {
		super(applicator);
	}

	@Override
	protected CallingConvention getCallingConvention(AbstractMsType type) {
		return ((AbstractProcedureMsType) type).getCallingConvention();
	}

	@Override
	protected RecordNumber getThisPointerRecordNumber(AbstractMsType type) {
		return null;
	}

	@Override
	protected RecordNumber getContainingComplexRecordNumber(AbstractMsType type) {
		return null;
	}

	@Override
	protected Pointer getThisPointer(AbstractMsType type) throws CancelledException, PdbException {
		return null;
	}

	@Override
	protected void processContainingType(AbstractMsType type) {
		return; // do nothing
	}

	@Override
	protected RecordNumber getReturnRecordNumber(AbstractMsType type) {
		return ((AbstractProcedureMsType) type).getReturnRecordNumber();
	}

	@Override
	protected RecordNumber getArgListRecordNumber(AbstractMsType type) {
		return ((AbstractProcedureMsType) type).getArgListRecordNumber();
	}

}
