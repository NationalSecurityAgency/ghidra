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

class OffsetReferenceDB extends MemReferenceDB implements OffsetReference {

	public OffsetReferenceDB(Program program, Address from, Address to, RefType refType,
			byte opIndex, SourceType sourceType, boolean isPrimary, long symbolID, long offset) {
		super(program, from, to, refType, opIndex, sourceType, isPrimary, symbolID, true, false,
			offset);
	}

	/**
	 * @see ghidra.program.model.symbol.OffsetReference#getOffset()
	 */
	public long getOffset() {
		return offsetOrShift;
	}

	/**
	 * @see ghidra.program.model.symbol.OffsetReference#getBaseAddress()
	 */
	public Address getBaseAddress() {
		return toAddr.subtractWrap(offsetOrShift);
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof OffsetReference)) {
			return false;
		}
		if (!super.equals(obj)) {
			return false;
		}
		OffsetReference ref = (OffsetReference) obj;
		return offsetOrShift == ref.getOffset();
	}
}
