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

import java.io.IOException;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.exception.InvalidInputException;

/**
 * A normal mapping of a HighSymbol to a particular Address, consuming a set number of bytes
 */
public class MappedEntry extends SymbolEntry {
	protected VariableStorage storage;

	/**
	 * For use with restoreXML
	 * @param sym is the owning symbol
	 */
	public MappedEntry(HighSymbol sym) {
		super(sym);
	}

	/**
	 * Construct given a symbol, storage, and first-use Address
	 * @param sym is the given symbol
	 * @param store is the given storage
	 * @param addr is the first-use Address (or null)
	 */
	public MappedEntry(HighSymbol sym, VariableStorage store, Address addr) {
		super(sym);
		storage = store;
		pcaddr = addr;
	}

	@Override
	public void decode(Decoder decoder) throws PcodeXMLException {
		HighFunction function = symbol.function;
		Program program = function.getFunction().getProgram();

		int addrel = decoder.openElement(ElementId.ELEM_ADDR);
		int sz = symbol.type.getLength();
		if (sz == 0) {
			throw new PcodeXMLException(
				"Invalid symbol 0-sized data-type: " + symbol.type.getName());
		}
		try {
			Address varAddr = AddressXML.decodeFromAttributes(decoder);
			AddressSpace spc = varAddr.getAddressSpace();
			if ((spc == null) || (spc.getType() != AddressSpace.TYPE_VARIABLE)) {
				storage = new VariableStorage(program, varAddr, sz);
			}
			else {
				decoder.rewindAttributes();
				storage = function.decodeVarnodePieces(decoder, varAddr);
			}
		}
		catch (InvalidInputException e) {
			throw new PcodeXMLException("Invalid storage: " + e.getMessage());
		}
		decoder.closeElement(addrel);

		decodeRangeList(decoder);
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		int logicalsize = 0; // Assume datatype size and storage size are the same
		int typeLength = symbol.type.getLength();
		if (typeLength != storage.size() && symbol.type instanceof AbstractFloatDataType) {
			logicalsize = typeLength; // Force a logicalsize
		}
		AddressXML.encode(encoder, storage.getVarnodes(), logicalsize);
		encodeRangelist(encoder);
	}

	@Override
	public VariableStorage getStorage() {
		return storage;
	}

	@Override
	public int getSize() {
		return storage.size();
	}

	@Override
	public boolean isReadOnly() {
		Address addr = storage.getMinAddress();
		if (addr == null) {
			return false;
		}
		boolean readonly = false;
		Program program = symbol.getProgram();
		MemoryBlock block = program.getMemory().getBlock(addr);
		if (block != null) {
			readonly = !block.isWrite();
			// if the block says read-only, check the refs to the variable
			// if the block says read-only, check the refs to the variable
			if (readonly) {
				ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(addr);
				int count = 0;
//				boolean foundRead = false;
				while (refIter.hasNext() && count < 100) {
					Reference ref = refIter.next();
					if (ref.getReferenceType().isWrite()) {
						readonly = false;
						break;
					}
					if (ref.getReferenceType().isRead()) {
//						foundRead = true;
					}
					count++;
				}
				// TODO: Don't do override if no read reference found
				//
				// if we only have indirect refs to it, don't assume readonly!
				//if (!foundRead && readonly && count > 1) {
				//	readonly = false;
				//}
				// they must be reading it multiple times for some reason
				// if (readonly && count > 1) {
				// 	readonly = false;
				// }
			}
		}
		return readonly;
	}

	@Override
	public boolean isVolatile() {
		Address addr = storage.getMinAddress();
		if (addr == null) {
			return false;
		}
		Program program = symbol.getProgram();
		if (program.getLanguage().isVolatile(addr)) {
			return true;
		}
		MemoryBlock block = program.getMemory().getBlock(addr);
		return (block != null && block.isVolatile());
	}
}
