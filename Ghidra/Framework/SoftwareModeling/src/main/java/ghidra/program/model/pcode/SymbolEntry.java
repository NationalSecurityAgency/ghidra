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

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.VariableStorage;

/**
 * A mapping from a HighSymbol object to the storage that holds the symbol's value.
 * 
 */
public abstract class SymbolEntry {
	protected HighSymbol symbol;	// The Symbol owning this entry
	protected Address pcaddr;		// Start of code range where this SymbolEntry applies

	/**
	 * Constructor for use with restoreXML
	 * @param sym is the symbol owning this entry
	 */
	public SymbolEntry(HighSymbol sym) {
		symbol = sym;
	}

	/**
	 * Decode this entry from the stream. Typically more than one element is consumed.
	 * @param decoder is the stream decoder
	 * @throws DecoderException for invalid encodings
	 */
	public abstract void decode(Decoder decoder) throws DecoderException;

	/**
	 * Encode this entry as (a set of) elements to the given stream
	 * @param encoder is the stream encoder
	 * @throws IOException for errors in the underlying stream
	 */
	public abstract void encode(Encoder encoder) throws IOException;

	/**
	 * Get the storage associated with this particular mapping of the Symbol
	 * @return the storage object
	 */
	public abstract VariableStorage getStorage();

	/**
	 * Get the number of bytes consumed by the symbol when using this storage
	 * @return the size of this entry
	 */
	public abstract int getSize();

	/**
	 * @return true if the mapped storage is read-only
	 */
	public abstract boolean isReadOnly();

	/**
	 * @return true if the mapped storage is volatile
	 */
	public abstract boolean isVolatile();

	/**
	 * The storage used to hold this Symbol may be used for other purposes at different points in
	 * the code.  This returns the earliest address in the code where this storage is used for this symbol
	 * @return the starting address where the Symbol uses this storage
	 */
	public Address getPCAdress() {
		return pcaddr;
	}

	protected void decodeRangeList(Decoder decoder) throws DecoderException {
		int rangelistel = decoder.openElement(ELEM_RANGELIST);
		if (decoder.peekElement() != 0) {
			// we only use this to establish first-use
			int rangeel = decoder.openElement(ELEM_RANGE);
			AddressSpace spc = decoder.readSpace(ATTRIB_SPACE);
			long offset = decoder.readUnsignedInteger(ATTRIB_FIRST);
			pcaddr = spc.getAddress(offset);
			pcaddr = symbol.function.getFunction()
					.getEntryPoint()
					.getAddressSpace()
					.getOverlayAddress(pcaddr);
			decoder.closeElement(rangeel);
		}

		decoder.closeElement(rangelistel);
	}

	protected void encodeRangelist(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_RANGELIST);
		if (pcaddr == null || pcaddr.isExternalAddress()) {
			encoder.closeElement(ELEM_RANGELIST);
			return;
		}
		AddressSpace space = pcaddr.getAddressSpace();
		long off;
		if (space.isOverlaySpace()) {
			space = space.getPhysicalSpace();
			off = space.getAddress(pcaddr.getOffset()).getUnsignedOffset();
		}
		else {
			off = pcaddr.getUnsignedOffset();
		}
		encoder.openElement(ELEM_RANGE);
		encoder.writeSpace(ATTRIB_SPACE, space);
		encoder.writeUnsignedInteger(ATTRIB_FIRST, off);
		encoder.writeUnsignedInteger(ATTRIB_LAST, off);
		encoder.closeElement(ELEM_RANGE);
		encoder.closeElement(ELEM_RANGELIST);
	}
}
