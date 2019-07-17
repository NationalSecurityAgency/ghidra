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

	public HighSymbol getSymbol() {
		return symbol;
	}

//	@Override
//	public void retype(DataType newtype, SourceType srctype) throws InvalidInputException {
//		Function f = getHighFunction().getFunction();
//		Varnode rep = getRepresentative();
//		Program program = f.getProgram();
//		newtype = newtype.clone(program.getDataTypeManager());
//		VariableStorage storage = rep.getStorage(program);
//		VariableStorage newStorage =
//			VariableUtilities.resizeStorage(storage, newtype, true, getHighFunction().getFunction());
//		Varnode newrep = getHighFunction().createFromPieces(newStorage);
//		Varnode[] inst = getInstances();
//		int pos;
//		for (pos = 0; pos < inst.length; ++pos)
//			if (inst[pos] == rep) {
//				inst[pos] = newrep;
//				break;
//			}
//		attachInstances(inst, newrep);
//		try {
//			super.retype(newtype, srctype);
//		}
//		catch (InvalidInputException e) {
//			if (pos < inst.length)
//				inst[pos] = rep;
//			attachInstances(inst, rep);				// Restore original varnode
//			throw e;
//		}
//	}

	/**
	 * @return instruction address the variable comes into scope within the function
	 */
	public Address getPCAddress() {
		return pcaddr;
	}

	protected int getFirstUseOffset() {
		Address pcaddr = getPCAddress();
		if (pcaddr == null || getRepresentative().getAddress().isStackAddress()) {
			return 0;
		}
		return (int) pcaddr.subtract(getHighFunction().getFunction().getEntryPoint());
	}

//	static DataType getUndefinedType(DataType originalType) {
//
//		// handle pointer conversion
//		if (originalType instanceof Pointer) {
//			Pointer ptr = (Pointer) originalType;
//			DataType innerDt = ptr.getDataType();
//			DataType replacementDt = innerDt;
//			if (!(originalType instanceof Undefined)) {
//				replacementDt = getUndefinedType(innerDt);
//			}
//			if (replacementDt != innerDt) {
//				return new PointerDataType(replacementDt, ptr.getLength(), ptr.getDataTypeManager());
//			}
//			return originalType;
//		}
//
//		int size = originalType.getLength();
//		if (size <= 8) {
//			return Undefined.getUndefinedDataType(size);
//		}
//		return originalType; // too big for undefined type
//	}

	@Override
	public VariableStorage getStorage() {

		Program program = getHighFunction().getFunction().getProgram();
		Varnode represent = getRepresentative();

		if (symbol instanceof DynamicSymbol || represent.isUnique()) {
			long hash = buildDynamicHash();
			try {
				return new VariableStorage(program, AddressSpace.HASH_SPACE.getAddress(hash),
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
