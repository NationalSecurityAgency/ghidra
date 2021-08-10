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
package ghidra.program.database.references;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.task.TaskMonitor;

class MemReferenceDB extends ReferenceDB {

	private Program program;
	private boolean isOffset;
	private boolean isShifted;
	protected long offsetOrShift;

	protected MemReferenceDB(Program program, Address fromAddr, Address toAddr, RefType refType,
			int opIndex, SourceType sourceType, boolean isPrimary, long symbolID, boolean isOffset,
			boolean isShifted, long offsetOrShift) {
		super(fromAddr, toAddr, refType, opIndex, sourceType, isPrimary, symbolID);
		this.program = program;
		this.isOffset = isOffset;
		this.isShifted = isShifted;
		this.offsetOrShift = offsetOrShift;

	}

	MemReferenceDB(Program program, Address from, Address to, RefType type, int opIndex,
			SourceType sourceType, boolean isPrimary, long symbolID) {
		this(program, from, to, type, opIndex, sourceType, isPrimary, symbolID, false, false, 0);
	}

	public boolean isOffset() {
		return isOffset;
	}

	public boolean isShifted() {
		return isShifted;
	}

	public long getOffsetOrShift() {
		return offsetOrShift;
	}

	/**
	 * @see ghidra.program.database.references.ReferenceDB#setProgram(ghidra.program.model.listing.Program)
	 */
	void setProgram(Program program) {
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isOffsetReference()
	 */
	@Override
	public boolean isOffsetReference() {
		return isOffset;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isShiftedReference()
	 */
	@Override
	public boolean isShiftedReference() {
		return isShifted;
	}

	/**
	 * @see java.lang.Object#equals(Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (obj instanceof MemReferenceDB) {
			MemReferenceDB memRef = (MemReferenceDB) obj;
			if (program == memRef.program) {
				return fromAddr.equals(memRef.getFromAddress()) &&
					toAddr.equals(memRef.getToAddress()) && opIndex == memRef.getOperandIndex() &&
					symbolID == memRef.getSymbolID() && isPrimary == memRef.isPrimary() &&
					sourceType == memRef.getSource() && refType == memRef.getReferenceType() &&
					isShiftedReference() == memRef.isShiftedReference() &&
					isOffsetReference() == memRef.isOffsetReference();
			}
			Address compatibleFromAddr =
				SimpleDiffUtility.getCompatibleAddress(program, fromAddr, memRef.program);
			if (compatibleFromAddr == null) {
				compatibleFromAddr = fromAddr;
			}
			if (!compatibleFromAddr.equals(memRef.fromAddr) || opIndex != memRef.opIndex ||
				sourceType != memRef.sourceType || refType != memRef.getReferenceType() ||
				toAddr.getOffset() != memRef.toAddr.getOffset() ||
				isPrimary != memRef.isPrimary() ||
				isShiftedReference() != memRef.isShiftedReference() ||
				isOffsetReference() != memRef.isOffsetReference()) {
				return false;
			}
			return true;
		}
		else if (obj instanceof Reference) {
			Reference ref = (Reference) obj;
			return fromAddr.equals(ref.getFromAddress()) && toAddr.equals(ref.getToAddress()) &&
				opIndex == ref.getOperandIndex() && symbolID == ref.getSymbolID() &&
				isPrimary == ref.isPrimary() && sourceType == ref.getSource() &&
				refType == ref.getReferenceType() &&
				isShiftedReference() == ref.isShiftedReference() &&
				isOffsetReference() == ref.isOffsetReference();
		}
		return false;

	}
}
