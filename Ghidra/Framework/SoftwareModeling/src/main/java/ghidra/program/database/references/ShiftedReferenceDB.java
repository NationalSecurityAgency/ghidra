/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

class ShiftedReferenceDB extends MemReferenceDB implements ShiftedReference {

	public ShiftedReferenceDB(Program program, Address from, Address to, RefType refType,
			byte opIndex, SourceType sourceType, boolean isPrimary, long symbolID, int shift) {
		super(program, from, to, refType, opIndex, sourceType, isPrimary, symbolID, false, true,
			shift);
	}

	/**
	 * @see ghidra.program.model.symbol.ShiftedReference#getShift()
	 */
	public int getShift() {
		return (int) offsetOrShift;
	}

	/**
	 * @see ghidra.program.model.symbol.ShiftedReference#getValue()
	 */
	public long getValue() {
		return toAddr.getOffset() >> (int) offsetOrShift;
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof ShiftedReference)) {
			return false;
		}
		if (!super.equals(obj)) {
			return false;
		}
		ShiftedReference ref = (ShiftedReference) obj;
		return offsetOrShift == ref.getShift();
	}
}
