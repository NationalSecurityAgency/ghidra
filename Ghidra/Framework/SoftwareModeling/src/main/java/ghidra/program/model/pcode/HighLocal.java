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
package ghidra.program.model.pcode;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.InvalidInputException;

public class HighLocal extends HighVariable {

	private Address pcaddr; // null or Address of PcodeOp which defines the representative
	private HighSymbol symbol;
	private long hash = 0; // 60-bit hash value, 0 indicates not-yet-computed or not-applicable

	public HighLocal(DataType type, Varnode vn, Varnode[] inst, Address pc, HighSymbol sym) {
		super(sym.getName(), type, vn, inst, sym.getHighFunction());
		pcaddr = pc;
		symbol = sym;
	}

	@Override
	public HighSymbol getSymbol() {
		return symbol;
	}

	/**
	 * @return instruction address the variable comes into scope within the function
	 */
	public Address getPCAddress() {
		return pcaddr;
	}

	protected int getFirstUseOffset() {
		if (pcaddr == null || getRepresentative().getAddress().isStackAddress()) {
			return 0;
		}
		return (int) pcaddr.subtract(getHighFunction().getFunction().getEntryPoint());
	}

	@Override
	public VariableStorage getStorage() {

		Program program = getHighFunction().getFunction().getProgram();
		Varnode represent = getRepresentative();

		if (symbol instanceof DynamicSymbol || represent.isUnique()) {
			long ourHash = buildDynamicHash();
			try {
				return new VariableStorage(program, AddressSpace.HASH_SPACE.getAddress(ourHash),
					represent.getSize());
			}
			catch (InvalidInputException e) {
				throw new AssertException("Unexpected exception", e);
			}
		}

		if (symbol instanceof MappedSymbol) {
			return ((MappedSymbol) symbol).getStorage();
		}

		return super.getStorage();
	}

	public long buildDynamicHash() {
		if (hash != 0) {
			return hash;
		}
		if (symbol instanceof DynamicSymbol) {
			hash = ((DynamicSymbol) symbol).getHash();
			pcaddr = symbol.getPCAddress();
		}
		else if (getRepresentative().isUnique()) {
			DynamicHash dynamicHash = new DynamicHash(getRepresentative(), getHighFunction());
			hash = dynamicHash.getHash();
			pcaddr = dynamicHash.getAddress();
		}
		return hash;
	}

}
