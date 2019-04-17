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
import ghidra.program.model.symbol.*;

class EntryPointReferenceDB extends ReferenceDB {

	public EntryPointReferenceDB(Address fromAddr, Address toAddr, RefType refType, int opIndex,
			SourceType sourceType, boolean isPrimary, long symbolID) {
		super(fromAddr, toAddr, refType, opIndex, sourceType, isPrimary, symbolID);
	}

	@Override
	public boolean isEntryPointReference() {
		return true;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (!(obj instanceof Reference)) {
			return false;
		}
		Reference ref = (Reference) obj;
		return isEntryPointReference() && fromAddr.equals(ref.getFromAddress()) &&
			toAddr.equals(ref.getToAddress()) && opIndex == ref.getOperandIndex() &&
			symbolID == ref.getSymbolID() && isPrimary == ref.isPrimary() &&
			sourceType == ref.getSource() && refType == ref.getReferenceType() &&
			isShiftedReference() == ref.isShiftedReference() &&
			isOffsetReference() == ref.isOffsetReference();
	}
}
