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
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.xml.SpecXmlUtils;

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
	 * @throws PcodeXMLException for invalid encodings
	 */
	public abstract void decode(Decoder decoder) throws PcodeXMLException;

	/**
	 * Save this entry as (a set of) XML tags to the given stream
	 * @param buf is the given stream
	 */
	public abstract void saveXml(StringBuilder buf);

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

	protected void decodeRangeList(Decoder decoder) throws PcodeXMLException {
		int rangelistel = decoder.openElement(ElementId.ELEM_RANGELIST);
		if (decoder.peekElement() != 0) {
			// we only use this to establish first-use
			int rangeel = decoder.openElement(ElementId.ELEM_RANGE);
			AddressSpace spc = decoder.readSpace(AttributeId.ATTRIB_SPACE);
			long offset = decoder.readUnsignedInteger(AttributeId.ATTRIB_FIRST);
			pcaddr = spc.getAddress(offset);
			pcaddr = symbol.function.getFunction()
					.getEntryPoint()
					.getAddressSpace()
					.getOverlayAddress(pcaddr);
			decoder.closeElement(rangeel);
		}

		decoder.closeElement(rangelistel);
	}

	protected void buildRangelistXML(StringBuilder res) {
		if (pcaddr == null || pcaddr.isExternalAddress()) {
			res.append("<rangelist/>");
			return;
		}
		res.append("<rangelist>");
		AddressSpace space = pcaddr.getAddressSpace();
		long off;
		if (space.isOverlaySpace()) {
			space = space.getPhysicalSpace();
			off = space.getAddress(pcaddr.getOffset()).getUnsignedOffset();
		}
		else {
			off = pcaddr.getUnsignedOffset();
		}
		res.append("<range");
		SpecXmlUtils.encodeStringAttribute(res, "space", space.getName());
		SpecXmlUtils.encodeUnsignedIntegerAttribute(res, "first", off);
		SpecXmlUtils.encodeUnsignedIntegerAttribute(res, "last", off);
		res.append("/>");
		res.append("</rangelist>\n");
	}
}
