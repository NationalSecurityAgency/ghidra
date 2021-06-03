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

import ghidra.program.model.address.*;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.exception.InvalidInputException;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

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
	public void restoreXML(XmlPullParser parser) throws PcodeXMLException {
		HighFunction function = symbol.function;
		Program program = function.getFunction().getProgram();
		AddressFactory addrFactory = function.getAddressFactory();

		XmlElement addrel = parser.start("addr");
		int sz = symbol.type.getLength();
		if (sz == 0) {
			throw new PcodeXMLException(
				"Invalid symbol 0-sized data-type: " + symbol.type.getName());
		}
		try {
			Address varAddr = AddressXML.readXML(addrel, addrFactory);
			AddressSpace spc = varAddr.getAddressSpace();
			if ((spc == null) || (spc.getType() != AddressSpace.TYPE_VARIABLE)) {
				storage = new VariableStorage(program, varAddr, sz);
			}
			else {
				storage = function.readXMLVarnodePieces(addrel, varAddr);
			}
		}
		catch (InvalidInputException e) {
			throw new PcodeXMLException("Invalid storage: " + e.getMessage());
		}
		parser.end(addrel);

		parseRangeList(parser);
	}

	@Override
	public void saveXml(StringBuilder buf) {
		int logicalsize = 0; // Assume datatype size and storage size are the same
		int typeLength = symbol.type.getLength();
		if (typeLength != storage.size() && symbol.type instanceof AbstractFloatDataType) {
			logicalsize = typeLength; // Force a logicalsize
		}
		AddressXML.buildXML(buf, storage.getVarnodes(), logicalsize);
		buildRangelistXML(buf);
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
