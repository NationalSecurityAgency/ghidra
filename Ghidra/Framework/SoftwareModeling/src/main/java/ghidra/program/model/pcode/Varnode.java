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

import java.util.Iterator;

import org.xml.sax.Attributes;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * Rawest possible Varnode.
 * Just a variable location and size, not part of a syntax tree.
 * A raw varnode is said to be free, it is not attached to any variable.
 */
public class Varnode {
	private static final long masks[] = { 0L, 0xffL, 0xffffL, 0xffffffL, 0xffffffffL, 0xffffffffffL,
		0xffffffffffffL, 0xffffffffffffffL, 0xffffffffffffffffL };

	private Address address;
	private int size;
	private int spaceID;
	private long offset;

	/**
	 * @param a location varnode attached to
	 * @param sz size of varnode
	 */
	public Varnode(Address a, int sz) {
		address = a;
		AddressSpace space = address.getAddressSpace();
		spaceID = space.getSpaceID();
		size = sz;
		offset = address.getOffset();
	}

	/**
	 * @param a location varnode attached to
	 * @param sz size of varnode
	 * @param symbolKey associated symbol key
	 */
	public Varnode(Address a, int sz, int symbolKey) {
		this(a, sz);
	}

	/**
	 * @return size of the varnode in bytes
	 */
	public int getSize() {
		return size;
	}

	/**
	 * @return the space this varnode belongs to (ram, register, ...)
	 */
	public int getSpace() {
		return spaceID;
	}

	/**
	 * @return the address this varnode is attached to
	 */
	public Address getAddress() {
		return address;
	}

	/**
	 * Get the address where this varnode is defined or
	 * NO_ADDRESS if this varnode is an input
	 * @return the address
	 */
	public Address getPCAddress() {
		if (isInput()) {
			return Address.NO_ADDRESS;
		}
		return getDef().getSeqnum().getTarget();
	}

	/**
	 * @return the offset into the address space varnode is defined within
	 */
	public long getOffset() {
		return offset;
	}

	/**
	 * Returns the word offset into the address space this is defined within
	 * 
	 * The word size is defined in the Language's .slaspec file with the
	 * "WORDSIZE" argument when DEFINEing a memory SPACE (capitalization is
	 * for emphasis; the directives are actually lowercase).
	 * 
	 * @return the word offset into the address space this is defined within
	 */
	public long getWordOffset() {
		return address.getAddressableWordOffset();
	}

	public boolean isFree() {
		return true;
	}

	/**
	 * Determine if this varnode contains the specified address
	 * @param address the address for which to check
	 * @return true if this varnode contains the specified address
	 */
	public boolean contains(Address address) {
		if (spaceID != address.getAddressSpace().getSpaceID()) {
			return false;
		}
		if (isConstant() || isUnique() || isHash()) {
			// this is not really a valid use case
			return offset == address.getOffset();
		}
		long endOffset = offset;
		if (size > 0) {
			endOffset = offset + size - 1;
		}
		long addrOffset = address.getOffset();
		if (offset > endOffset) { // handle long-wrap condition
			return offset <= addrOffset;
		}
		return offset <= addrOffset && endOffset >= addrOffset;
	}

	/**
	 * Determine if this varnode intersects another varnode.  
	 * @param varnode other varnode
	 * @return true if this varnode intersects the specified varnode
	 */
	public boolean intersects(Varnode varnode) {
		if (spaceID != varnode.spaceID) {
			return false;
		}
		if (isConstant() || isUnique() || isHash()) {
			// this is not really a valid use case
			return offset == varnode.getOffset();
		}
		long endOtherOffset = varnode.offset;
		if (varnode.size > 0) {
			endOtherOffset = varnode.offset + varnode.size - 1;
		}
		return rangeIntersects(varnode.offset, endOtherOffset);
	}

	private boolean rangeIntersects(long otherOffset, long otherEndOffset) {
		long endOffset = offset;
		if (size > 0) {
			endOffset = offset + size - 1;
		}
		if (offset > endOffset) { // handle long-wrap condition
			if (otherOffset > otherEndOffset) {
				return true; // both wrapped - must intersect
			}
			return offset <= otherEndOffset;
		}
		if (otherOffset > otherEndOffset) { // handle wrap condition
			return endOffset >= otherOffset;
		}
		return offset <= otherEndOffset && endOffset >= otherOffset;
	}

	/**
	 * Determine if this varnode intersects the specified address set
	 * @param set address set
	 * @return true if this varnode intersects the specified address set
	 */
	public boolean intersects(AddressSetView set) {
		if (isConstant() || isUnique() || isHash() || set == null || set.isEmpty()) {
			return false;
		}
		for (AddressRange range : set.getAddressRanges()) {
			Address minAddr = range.getMinAddress();
			if (minAddr.getAddressSpace().getSpaceID() != spaceID) {
				continue;
			}
			Address maxAddr = range.getMaxAddress();
			if (rangeIntersects(minAddr.getOffset(), maxAddr.getOffset())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @return true if this varnode exists in a Memory space (vs. register etc...).
	 * Keep in mind this varnode may also correspond to a defined register 
	 * if true is returned and {@link #isRegister()} return false.  
	 * Memory-based registers may be indirectly addressed which leads to the 
	 * distinction with registers within the register space.
	 */
	public boolean isAddress() {
		int type = AddressSpace.ID_TYPE_MASK & spaceID;
		return type == AddressSpace.TYPE_RAM;
	}

	/**
	 * @return true if this varnode exists in a Register type space.
	 * If false is returned, keep in mind this varnode may still correspond to a 
	 * defined register within a memory space.  Memory-based registers may be indirectly 
	 * addressed which leads to the distinction with registers within the register space.
	 */
	public boolean isRegister() {
		int type = AddressSpace.ID_TYPE_MASK & spaceID;
		return (type == AddressSpace.TYPE_REGISTER);
	}

	/**
	 * @return true if this varnode is just a constant number
	 */
	public boolean isConstant() {
		int type = AddressSpace.ID_TYPE_MASK & spaceID;
		return (type == AddressSpace.TYPE_CONSTANT);
	}

	/**
	 * @return true if this varnode doesn't exist anywhere.  A temporary variable.
	 */
	public boolean isUnique() {
		int type = AddressSpace.ID_TYPE_MASK & spaceID;
		return (type == AddressSpace.TYPE_UNIQUE);
	}

	public boolean isHash() {
		return spaceID == AddressSpace.HASH_SPACE.getSpaceID();
	}

	/**
	 * @return is input to a pcode op
	 */
	public boolean isInput() {
		return false;				// Not a valid query with a free varnode
	}

	/**
	 * @return is persistant
	 */
	public boolean isPersistant() {
		return false;				// Not a valid query with a free varnode
	}

	/**
	 * @return is mapped to an address
	 */
	public boolean isAddrTied() {
		return false;				// Not a valid query with a free varnode
	}

	public boolean isUnaffected() {
		return false;				// Not a valid query with a free varnode
	}

	/**
	 * @return get the pcode op this varnode belongs to
	 */
	public PcodeOp getDef() {
		return null;					// Not a valid query with a free varnode
	}

	/**
	 * @return iterator to all PcodeOp s that take this as input
	 */
	public Iterator<PcodeOp> getDescendants() {
		return null;					// Not a valid query with a free varnode
	}

	/**
	 * If there is only one PcodeOp taking this varnode as input, return it. Otherwise return null
	 * @return the lone descendant PcodeOp
	 */
	public PcodeOp getLoneDescend() {
		Iterator<PcodeOp> iter = getDescendants();
		if (!iter.hasNext()) {
			return null;		// If there are no descendants return null
		}
		PcodeOp op = iter.next();
		if (iter.hasNext()) {
			return null;		// If there is more than one descendant return null
		}
		return op;
	}

	/**
	 * @return the high level variable this varnode represents
	 */
	public HighVariable getHigh() {
		return null;
	}

	/**
	 * @return the index of the group, within the high containing this, that are forced merged with this  
	 */
	public short getMergeGroup() {
		return 0;
	}

	/**
	 * @param buf is the builder to which to append XML
	 */
	public void buildXML(StringBuilder buf) {
		buildXMLAddress(buf, address, size);
	}

	/**
	 * Build an XML document representation of a varnode with the given address and size.
	 * 
	 * @param resBuf is the builder to which to append the XML
	 * @param addr location varnode is defined at
	 * @param size size of the varnode.
	 */
	public static void buildXMLAddress(StringBuilder resBuf, Address addr, int size) {
		resBuf.append("<addr");
		appendSpaceOffset(resBuf, addr);
		SpecXmlUtils.encodeSignedIntegerAttribute(resBuf, "size", size);
		resBuf.append("/>");
	}

	/**
	 * Convert an address into an XML document.
	 * 
	 * @param addr -- Address to convert to XML
	 * @return XML string
	 */
	public static String buildXMLAddress(Address addr) {

		if ((addr == null) || (addr == Address.NO_ADDRESS)) {
			return "<addr/>";
		}
		StringBuilder resBuf = new StringBuilder();
		resBuf.append("<addr");
		appendSpaceOffset(resBuf, addr);
		resBuf.append("/>");
		return resBuf.toString();
	}

	/**
	 * Convert a varnode array into an XML document.
	 * 
	 * @param varnodes sequence of storage varnodes
	 * @param logicalsize the logical size value of the varnode
	 * @return XML string
	 */
	public static String buildXMLAddress(Varnode[] varnodes, int logicalsize) {

		if (varnodes == null) {
			return "<addr/>";
		}
		if ((varnodes.length == 1) && (logicalsize == 0)) {
			StringBuilder buf = new StringBuilder();
			buildXMLAddress(buf, varnodes[0].address, varnodes[0].size);
			return buf.toString();
		}
		StringBuilder resBuf = new StringBuilder();
		resBuf.append("<addr space=\"join\"");
		int piece = 0;
		for (Varnode vn : varnodes) {
			resBuf.append(" piece");
			resBuf.append(Integer.toString(++piece));
			resBuf.append("=\"");
			buildVarnodePiece(resBuf, vn.address, vn.size);
			resBuf.append("\"");
		}
		if (logicalsize != 0) {
			resBuf.append(" logicalsize=\"").append(logicalsize).append('\"');
		}
		resBuf.append("/>");
		return resBuf.toString();
	}

	private static void buildVarnodePiece(StringBuilder buf, Address addr, int size) {
		AddressSpace space = addr.getAddressSpace();
		if (space.isOverlaySpace()) {
			space = space.getPhysicalSpace();
			addr = space.getAddress(addr.getOffset());
		}
		buf.append(space.getName());
		buf.append(":0x");
		long off = addr.getUnsignedOffset();
		buf.append(Long.toHexString(off));
		buf.append(':');
		buf.append(Integer.toString(size));
	}

	public static void appendSpaceOffset(StringBuilder buf, Address addr) {
		AddressSpace space = addr.getAddressSpace();
		if (space.isOverlaySpace()) {
			if (space.getType() != AddressSpace.TYPE_OTHER) {
				space = space.getPhysicalSpace();
				addr = space.getAddress(addr.getOffset());
			}
		}
		SpecXmlUtils.encodeStringAttribute(buf, "space", space.getName());
		SpecXmlUtils.encodeUnsignedIntegerAttribute(buf, "offset", addr.getUnsignedOffset());
	}

	/**
	 * Build a varnode from a SAX parse tree node
	 * 
	 * @param parser the parser
	 * @param factory pcode factory used to create valid pcode
	 * 
	 * @return new varnode element based on info in the XML.
	 * 
	 * @throws PcodeXMLException
	 */
	public static Varnode readXML(XmlPullParser parser, PcodeFactory factory)
			throws PcodeXMLException {
		XmlElement el = parser.start();
		try {
			if (el.getName().equals("void")) {
				return null;
			}
			Varnode vn;
			String attrstring = el.getAttribute("ref");
			int ref = -1;
			if (attrstring != null) {
				ref = SpecXmlUtils.decodeInt(attrstring);	// If we have a reference
				vn = factory.getRef(ref);											// The varnode may already exist
				if (vn != null) {
					return vn;
				}
			}
			Address addr = readXMLAddress(el, factory.getAddressFactory());
			if (addr == null) {
				return null;
			}
			int sz;
			attrstring = el.getAttribute("size");
			if (attrstring != null) {
				sz = SpecXmlUtils.decodeInt(attrstring);
			}
			else {
				sz = 4;
			}
			if (ref != -1) {
				vn = factory.newVarnode(sz, addr, ref);
			}
			else {
				vn = factory.newVarnode(sz, addr);
			}
			AddressSpace spc = addr.getAddressSpace();
			if ((spc != null) && (spc.getType() == AddressSpace.TYPE_VARIABLE)) {	// Check for a composite Address
				try {
					factory.readXMLVarnodePieces(el, addr);
				}
				catch (InvalidInputException e) {
					throw new PcodeXMLException("Invalid varnode pieces: " + e.getMessage());
				}
			}
			attrstring = el.getAttribute("grp");
			if (attrstring != null) {
				short val = (short) SpecXmlUtils.decodeInt(attrstring);
				factory.setMergeGroup(vn, val);
			}
			attrstring = el.getAttribute("persists");
			if ((attrstring != null) && (SpecXmlUtils.decodeBoolean(attrstring))) {
				factory.setPersistant(vn, true);
			}
			attrstring = el.getAttribute("addrtied");
			if ((attrstring != null) && (SpecXmlUtils.decodeBoolean(attrstring))) {
				factory.setAddrTied(vn, true);
			}
			attrstring = el.getAttribute("unaff");
			if ((attrstring != null) && (SpecXmlUtils.decodeBoolean(attrstring))) {
				factory.setUnaffected(vn, true);
			}
			attrstring = el.getAttribute("input");
			if ((attrstring != null) && (SpecXmlUtils.decodeBoolean(attrstring))) {
				vn = factory.setInput(vn, true);
			}
			return vn;
		}
		finally {
			parser.end(el);
		}
	}

	/**
	 * Trim a varnode in a constant space to the correct starting offset.
	 * 
	 * Constant handles may contain constants of indeterminate size.
	 * This is where the size gets fixed, i.e. we mask off the constant
	 * to its proper size.  A varnode that is ends up in pcode should
	 * call this method to ensure that varnodes always contains raw data.
	 * On the other hand, varnodes in handles are allowed to have offsets
	 * that violate size restrictions.
	 */
	public void trim() {
		if (address.getAddressSpace().getType() == AddressSpace.TYPE_CONSTANT) {
			offset = offset & masks[size];
			address = address.getNewAddress(offset);
		}
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return ("(" + address.getAddressSpace().getName() + ", 0x" + Long.toHexString(offset) +
			", " + size + ")");
	}

	/**
	 * Convert this varnode to an alternate String representation based on a specified language.
	 * @param language
	 * @return string representation
	 */
	public String toString(Language language) {
		if (isAddress() || isRegister()) {
			Register reg = language.getRegister(address, size);
			if (reg != null) {
				return reg.getName();
			}
		}
		if (isUnique()) {
			return "u_" + Long.toHexString(offset) + ":" + size;
		}
		if (isConstant()) {
			return "0x" + Long.toHexString(offset);
		}
		return "A_" + address + ":" + size;
	}

	@Override
	public boolean equals(Object o) {
		//
		// Note: it is not clear if the equals/hashCode currently work correctly when used in 
		//       OverlayAddressSpaces.  There is a ticket to examine this issue.
		//

		if (o == this) {
			return true;
		}
		if (!(o instanceof Varnode)) {
			return false;
		}

		Varnode vn = (Varnode) o;
		if (!vn.isFree()) {
			return false;
		}

		return (this.offset == vn.getOffset() && this.size == vn.getSize() &&
			this.spaceID == vn.getSpace());
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (int) (offset ^ (offset >>> 32));
		result = prime * result + size;
		result = prime * result + spaceID;
		return result;
	}

	/**
	 * Create an address from a SAX parse tree node.
	 * 
	 * @param el SAX parse tree element
	 * @param addrFactory address factory used to create valid addresses
	 * @return Address created from XML info
	 */
	public static Address readXMLAddress(XmlElement el, AddressFactory addrFactory) {
		String localName = el.getName();
		if (localName.equals("spaceid")) {
			AddressSpace spc = addrFactory.getAddressSpace(el.getAttribute("name"));
			int spaceid = spc.getSpaceID();
			spc = addrFactory.getConstantSpace();
			return spc.getAddress(spaceid);
		}
		else if (localName.equals("iop")) {
			int ref = SpecXmlUtils.decodeInt(el.getAttribute("value"));
			AddressSpace spc = addrFactory.getConstantSpace();
			return spc.getAddress(ref);
		}
		String space = el.getAttribute("space");
		if (space == null) {
			return Address.NO_ADDRESS;
		}
		long offset = SpecXmlUtils.decodeLong(el.getAttribute("offset"));
		AddressSpace spc = addrFactory.getAddressSpace(space);
		if (spc == null) {
			return null;
		}
		return spc.getAddress(offset);
	}

	public static Address readXMLAddress(String localName, Attributes attr,
			AddressFactory addrFactory) {
		if (localName.equals("spaceid")) {
			AddressSpace spc = addrFactory.getAddressSpace(attr.getValue("name"));
			int spaceid = spc.getSpaceID();
			spc = addrFactory.getConstantSpace();
			return spc.getAddress(spaceid);
		}
		else if (localName.equals("iop")) {
			int ref = SpecXmlUtils.decodeInt(attr.getValue("value"));
			AddressSpace spc = addrFactory.getConstantSpace();
			return spc.getAddress(ref);
		}
		String space = attr.getValue("space");
		if (space == null) {
			return Address.NO_ADDRESS;
		}
		long offset = SpecXmlUtils.decodeLong(attr.getValue("offset"));
		AddressSpace spc = addrFactory.getAddressSpace(space);
		if (spc == null) {
			return Address.NO_ADDRESS;
		}
		return spc.getAddress(offset);
	}

	/**
	 * Parse an XML containing an address.  The format options are simple enough that we don't try to invoke
	 * an actual XML parser but just walk the string
	 * @param addrstring  is the string containing the XML tag
	 * @param addrfactory is the factory that can produce addresses
	 * @param refSpace can be null but is otherwise the reference AddressSpace from which the request is sent.
	 * @return the created Address or Address.NO_ADDRESS in some special cases
	 * @throws PcodeXMLException
	 */
	public static Address readXMLAddress(String addrstring, AddressFactory addrfactory,
			AddressSpace refSpace) throws PcodeXMLException {

		int tagstart = addrstring.indexOf('<');
		if (tagstart >= 0) {
			tagstart += 1;
			if (addrstring.startsWith("spaceid", tagstart)) {
				tagstart += 8;
				int attrstart = addrstring.indexOf("name=\"", tagstart);
				if (attrstart >= 0) {
					attrstart += 6;
					int nameend = addrstring.indexOf('\"', attrstart);
					if (nameend >= 0) {
						AddressSpace spc =
							addrfactory.getAddressSpace(addrstring.substring(attrstart, nameend));
						int spaceid = spc.getSpaceID();
						spc = addrfactory.getConstantSpace();
						return spc.getAddress(spaceid);
					}
				}

			}
			// There are several tag forms where we essentially want to just look for 'space' and 'offset' attributes
			// don't explicitly check the tag name
			int spacestart = addrstring.indexOf("space=\"");
			if (spacestart >= 4) {
				spacestart += 7;
				int spaceend = addrstring.indexOf('"', spacestart);
				if (spaceend >= spacestart) {
					String spcname = addrstring.substring(spacestart, spaceend);
					int offstart = addrstring.indexOf("offset=\"");
					if (offstart >= 4) {
						offstart += 8;
						int offend = addrstring.indexOf('"', offstart);
						if (offend >= offstart) {
							String offstr = addrstring.substring(offstart, offend);
							AddressSpace spc = addrfactory.getAddressSpace(spcname);
							// Unknown spaces may result from "spacebase" registers defined in cspec
							if (spc == null) {
								return Address.NO_ADDRESS;
							}
							long offset = SpecXmlUtils.decodeLong(offstr);
							Address addr = spc.getAddress(offset);
							if (refSpace != null && refSpace.isOverlaySpace()) {
								return refSpace.getOverlayAddress(addr);
							}
							return addr;
						}
					}
				}
			}
		}
		throw new PcodeXMLException("Badly formed address: " + addrstring);
	}
}
