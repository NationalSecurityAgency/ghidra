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

class StackReferenceDB extends MemReferenceDB implements StackReference {

	StackReferenceDB(Program program, Address fromAddr, Address toAddr, RefType refType,
			int opIndex, SourceType sourceType, boolean isPrimary, long symbolID) {
		super(program, fromAddr, toAddr, refType, opIndex, sourceType, isPrimary, symbolID);
	}

	/**
	 * @see ghidra.program.model.symbol.StackReference#getStackOffset()
	 */
	public int getStackOffset() {
		return (int) toAddr.getOffset();
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isStackReference()
	 */
	@Override
	public boolean isStackReference() {
		return true;
	}
}
