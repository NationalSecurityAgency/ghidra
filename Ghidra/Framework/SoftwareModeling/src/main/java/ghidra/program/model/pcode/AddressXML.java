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

import java.util.ArrayList;

import org.xml.sax.Attributes;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlParseException;

/**
 * Utility class for the myriad ways of marshaling/unmarshaling an address and an optional size,
 * to/from XML for the various configuration files.
 * 
 * An object of the class itself is the most general form, where the specified address
 *   - MAY have an associated size given in bytes
 *   - MAY be in the JOIN address space, with physical pieces making up the logical value explicitly provided.
 * 
 * The static buildXML methods write out an \<addr> tag given component elements without allocating an object.
 * The static readXML methods read XML tags (presented in different forms) and returns an Address object.
 * The static appendAttributes methods write out attributes of an address to an arbitrary XML tag.
 * The static restoreXML methods read an \<addr> tag and produce a general AddressXML object.
 */
public class AddressXML {
	private AddressSpace space;		// Address space containing the memory range
	private long offset;			// Starting offset of the range
	private long size;				// Number of bytes in the size
	private Varnode[] joinRecord;	// If non-null, separate address ranges being bonded in the "join" space

	/**
	 * Internal constructor for incremental initialization
	 */
	private AddressXML() {
		space = null;
		joinRecord = null;
	}

	/**
	 * Construct an Address range as a space/offset/size
	 * @param spc is the address space containing the range
	 * @param off is the starting byte offset of the range
	 * @param sz is the size of the range in bytes
	 */
	public AddressXML(AddressSpace spc, long off, int sz) {
		space = spc;
		offset = off;
		size = sz;
		joinRecord = null;
	}

	/**
	 * Construct a logical memory range, representing multiple ranges pieced together.
	 * The logical range is assigned an address in the JOIN address space.
	 * The physical pieces making up the logical range are passed in as a sequence of
	 * Varnodes representing, in order, the most significant through the least significant
	 * portions of the value.
	 * @param spc is the JOIN address space (must have a type of AddressSpace.TYPE_JOIN)
	 * @param off is the offset of the logical value within the JOIN space
	 * @param sz is the number of bytes in the logical value
	 * @param pieces is the array of 1 or more physical pieces
	 */
	public AddressXML(AddressSpace spc, long off, int sz, Varnode[] pieces) {
		if (spc.getType() != AddressSpace.TYPE_JOIN) {
			throw new IllegalArgumentException(
				"JOIN address space required to represent an Address with pieces");
		}
		space = spc;
		offset = off;
		size = sz;
		joinRecord = pieces;
	}

	private void readJoinXML(XmlElement el, CompilerSpec cspec) throws XmlParseException {
		ArrayList<Varnode> pieces = new ArrayList<>();
		int sizesum = 0;
		int pos = 0;
		for (;;) {
			String attrName = "piece" + Integer.toString(pos + 1);
			String attrVal = el.getAttribute(attrName);
			if (attrVal == null) {
				break;
			}
			int offpos = attrVal.indexOf(':');
			Varnode newvn;
			if (offpos == -1) {
				Register register = cspec.getLanguage().getRegister(attrVal);
				if (register == null) {
					throw new XmlParseException("Unknown pentry register: " + attrVal);
				}
				newvn = new Varnode(register.getAddress(), register.getBitLength() / 8);
			}
			else {
				int szpos = attrVal.indexOf(':', offpos + 1);
				if (szpos == -1) {
					throw new XmlParseException("join address piece attribute is malformed");
				}
				String spcname = attrVal.substring(0, offpos);
				AddressSpace spc = cspec.getAddressSpace(spcname);
				long off = SpecXmlUtils.decodeLong(attrVal.substring(offpos + 1, szpos));
				long sz = SpecXmlUtils.decodeLong(attrVal.substring(szpos + 1));
				newvn = new Varnode(spc.getAddress(off), (int) sz);
			}
			pieces.add(newvn);
			sizesum += newvn.getSize();
			pos += 1;
		}
		offset = 0;		// This should be the offset assigned by the join space
		size = sizesum;	// Size is sum unless explicit attribute overwrites this with logical size
		joinRecord = new Varnode[pieces.size()];
		pieces.toArray(joinRecord);
	}

	/**
	 * Write this sized address as an \<addr> XML tag.
	 * @param buffer is the buffer to write to
	 */
	public void saveXml(StringBuilder buffer) {
		if (joinRecord != null) {
			long logicalSize = size;
			long sizeSum = 0;
			for (Varnode vn : joinRecord) {
				sizeSum += vn.getSize();
			}
			if (sizeSum == size) {
				logicalSize = 0;
			}
			buildXML(buffer, joinRecord, logicalSize);
			return;
		}
		buffer.append("<addr");
		if (space != null) {
			SpecXmlUtils.encodeStringAttribute(buffer, "space", space.getName());
			SpecXmlUtils.encodeUnsignedIntegerAttribute(buffer, "offset", offset);
			if (size != 0) {
				SpecXmlUtils.encodeSignedIntegerAttribute(buffer, "size", size);
			}
		}
		buffer.append("/>");
	}

	/**
	 * Restore an Address (as an AddressSpace and an offset) and an optional size from XML tag.
	 * The tag can have any name, but it must either have:
	 *    - A "name" attribute, indicating a register name  OR
	 *    - A "space" and "offset" attribute, indicating the address space and offset
	 *    
	 * If a register name is given, size is obtained from the register.  If an offset is
	 * given, the size can optionally be specified using a "size" attribute.
	 * If not explicitly described, the size is set to zero.
	 * 
	 * This method supports the "join" address space attached to the compiler specification
	 * @param el is the XML tag
	 * @param cspec is the compiler spec for looking up registers
	 * @return an AddressXML object containing the recovered space,offset,size
	 * @throws XmlParseException for problems parsing
	 */
	public static AddressXML restoreXml(XmlElement el, CompilerSpec cspec)
			throws XmlParseException {
		AddressXML result;
		if (el.getName().equals("register")) {
			String regName = el.getAttribute("name");
			if (regName == null) {
				throw new XmlParseException("Missing pentry register name");
			}
			Register register = cspec.getLanguage().getRegister(regName);
			if (register == null) {
				throw new XmlParseException("Unknown pentry register: " + regName);
			}
			result = new AddressXML(register.getAddressSpace(), register.getOffset(),
				register.getMinimumByteSize());
		}
		else {
			result = new AddressXML();
			result.size = 0;
			String spaceName = el.getAttribute("space");
			result.space = cspec.getAddressSpace(spaceName);
			if (result.space == null) {
				throw new XmlParseException("Unknown address space: " + spaceName);
			}
			if (result.space.getType() == AddressSpace.TYPE_JOIN) {
				result.readJoinXML(el, cspec);
			}
			else {
				result.offset = SpecXmlUtils.decodeLong(el.getAttribute("offset"));
			}
			String sizeString = el.getAttribute("size");
			if (sizeString != null) {
				result.size = SpecXmlUtils.decodeInt(sizeString);
			}
		}
		return result;
	}

	/**
	 * Restore an Address (as an AddressSpace and an offset) and an optional size from XML tag.
	 * The tag can have any name, but it must either have:
	 *    - A "name" attribute, indicating a register name  OR
	 *    - A "space" and "offset" attribute, indicating the address space and offset
	 *    
	 * If a register name is given, size is obtained from the register.  If an offset is
	 * given, the size can optionally be specified using a "size" attribute.
	 * If not explicitly described, the size is set to zero.
	 * @param el is the XML tag
	 * @param language is the processor language for looking up registers and address spaces
	 * @return an AddressXML object containing the recovered space,offset,size
	 * @throws XmlParseException for problems parsing
	 */
	public static AddressXML restoreXml(XmlElement el, Language language) throws XmlParseException {
		AddressXML result;
		if (el.getName().equals("register")) {
			String regName = el.getAttribute("name");
			if (regName == null) {
				throw new XmlParseException("Missing register name");
			}
			Register register = language.getRegister(regName);
			if (register == null) {
				throw new XmlParseException("Unknown register: " + regName);
			}
			result = new AddressXML(register.getAddressSpace(), register.getOffset(),
				register.getMinimumByteSize());
		}
		else {
			result = new AddressXML();
			result.size = 0;
			String spaceName = el.getAttribute("space");
			result.space = language.getAddressFactory().getAddressSpace(spaceName);
			if (result.space == null) {
				throw new XmlParseException("Unknown address space: " + spaceName);
			}
			result.offset = SpecXmlUtils.decodeLong(el.getAttribute("offset"));
			String sizeString = el.getAttribute("size");
			if (sizeString != null) {
				result.size = SpecXmlUtils.decodeInt(sizeString);
			}
		}
		return result;
	}

	/**
	 * A memory range is read from attributes of an XML tag. The tag must either have:
	 *    - "name" attribute - indicating a register 
	 *    - "space" attribute - with optional "first" and "last" attributes
	 * 
	 * With the "space" attribute, "first" defaults to 0 and "last" defaults to the last offset in the space.
	 * @param el is the XML element
	 * @param cspec is a compiler spec to resolve address spaces and registers
	 * @return an AddressXML object representing the range
	 * @throws XmlParseException if the XML is badly formed
	 */
	public static AddressXML restoreRangeXml(XmlElement el, CompilerSpec cspec)
			throws XmlParseException {
		AddressXML result = new AddressXML();
		result.offset = 0;
		long last = -1;
		boolean seenLast = false;
		String attrvalue = el.getAttribute("space");
		if (attrvalue != null) {
			result.space = cspec.getAddressSpace(attrvalue);
			if (result.space == null) {
				throw new XmlParseException("Undefined space: " + attrvalue);
			}
		}
		attrvalue = el.getAttribute("first");
		if (attrvalue != null) {
			result.offset = SpecXmlUtils.decodeLong(attrvalue);
		}
		attrvalue = el.getAttribute("last");
		if (attrvalue != null) {
			last = SpecXmlUtils.decodeLong(attrvalue);
			seenLast = true;
		}
		attrvalue = el.getAttribute("name");
		if (attrvalue != null) {
			Register register = cspec.getLanguage().getRegister(attrvalue);
			result.space = register.getAddressSpace();
			result.offset = register.getOffset();
			last = (result.offset - 1) + register.getMinimumByteSize();
			seenLast = true;
		}
		if (result.space == null) {
			throw new XmlParseException("No address space indicated in range tag");
		}
		if (!seenLast) {
			last = result.space.getMaxAddress().getOffset();
		}
		result.size = (last - result.offset) + 1;
		return result;
	}

	/**
	 * @return the space associated of this address
	 */
	public final AddressSpace getAddressSpace() {
		return space;
	}

	/**
	 * @return the byte offset of this address
	 */
	public final long getOffset() {
		return offset;
	}

	/**
	 * @return the size in bytes associated with this address
	 */
	public final long getSize() {
		return size;
	}

	/**
	 * Get the array of physical pieces making up this logical address range, if
	 * the range is in the JOIN address space. Otherwise return null.
	 * @return the physical pieces or null
	 */
	public final Varnode[] getJoinRecord() {
		return joinRecord;
	}

	/**
	 * Build a raw Varnode from the Address and size
	 * @return the new Varnode
	 */
	public Varnode getVarnode() {
		Address addr = space.getAddress(offset);
		return new Varnode(addr, (int) size);
	}

	/**
	 * @return the first address in the range
	 */
	public Address getFirstAddress() {
		return space.getAddress(offset);
	}

	/**
	 * @return the last address in the range
	 */
	public Address getLastAddress() {
		return space.getAddress(offset + size - 1);
	}

	/**
	 * Parse String containing an XML tag representing an Address.
	 * The format options are simple enough that we don't try to invoke
	 * an actual XML parser but just walk the string. This recognizes
	 *   - \<addr>
	 *   - \<spaceid> or
	 *   - any tag with a "space" and "offset" attribute
	 * 
	 * @param addrstring  is the string containing the XML tag
	 * @param addrfactory is the factory that can produce addresses
	 * @return the created Address or Address.NO_ADDRESS in some special cases
	 * @throws PcodeXMLException for a badly formed Address
	 */
	public static Address readXML(String addrstring, AddressFactory addrfactory)
			throws PcodeXMLException {

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
							return spc.getAddress(offset);
						}
					}
				}
			}
		}
		throw new PcodeXMLException("Badly formed address: " + addrstring);
	}

	/**
	 * Read the (first) size attribute from an XML tag string as an integer
	 * @param addrxml is the XML string
	 * @return the decoded integer or zero if the attribute doesn't exist
	 */
	public static int readXMLSize(String addrxml) {
		int attrstart = addrxml.indexOf("size=\"");
		if (attrstart >= 4) {
			attrstart += 6;
			int attrend = addrxml.indexOf('\"', attrstart);
			if (attrend > attrstart) {
				int size = SpecXmlUtils.decodeInt(addrxml.substring(attrstart, attrend));
				return size;
			}
		}
		return 0;
	}

	/**
	 * Create an address from an XML parse tree node. This recognizes XML tags
	 *   - \<addr>
	 *   - \<spaceid>
	 *   - \<iop> or
	 *   - any tag with "space" and "offset" attributes
	 * 
	 * An empty \<addr> tag, with no attributes, results in Address.NO_ADDRESS being returned.
	 * @param el is the parse tree element
	 * @param addrFactory address factory used to create valid addresses
	 * @return Address created from XML info
	 */
	public static Address readXML(XmlElement el, AddressFactory addrFactory) {
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

	/**
	 * Read an Address given an XML tag name and its attributes. This recognizes XML tags
	 *   - \<addr>
	 *   - \<spaceid>
	 *   - \<iop>
	 *   - any tag with "space" or "offset" attributes
	 * 
	 * An empty \<addr> tag, with no attributes, results in Address.NO_ADDRESS being returned.
	 * @param localName is the name of the tag
	 * @param attr is the collection of attributes for the tag
	 * @param addrFactory is an Address factory
	 * @return the scanned address
	 */
	public static Address readXML(String localName, Attributes attr, AddressFactory addrFactory) {
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
	 * Append "space" and "offset" attributes describing the given Address to the XML stream.
	 * This assumes the XML tag name has already been emitted.
	 * @param buf is the XML stream
	 * @param addr is the given Address
	 */
	public static void appendAttributes(StringBuilder buf, Address addr) {
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
	 * Append "space" "offset" and "size" attributes describing the given memory range to the XML stream.
	 * This assumes the XML tag name has already been emitted.
	 * @param buf is the XML stream
	 * @param addr is the starting Address of the memory range
	 * @param size is the size of the memory range
	 */
	public static void appendAttributes(StringBuilder buf, Address addr, int size) {
		AddressSpace space = addr.getAddressSpace();
		if (space.isOverlaySpace()) {
			if (space.getType() != AddressSpace.TYPE_OTHER) {
				space = space.getPhysicalSpace();
				addr = space.getAddress(addr.getOffset());
			}
		}
		SpecXmlUtils.encodeStringAttribute(buf, "space", space.getName());
		SpecXmlUtils.encodeUnsignedIntegerAttribute(buf, "offset", addr.getUnsignedOffset());
		SpecXmlUtils.encodeSignedIntegerAttribute(buf, "size", size);
	}

	/**
	 * Append a memory range, as "space", "first", and "last" attributes, to the XML stream.
	 * This assumes the XML tag name has already been emitted.
	 * @param buffer is the XML stream
	 * @param startAddr is the first address in the range
	 * @param endAddr is the last address in the range
	 */
	public static void appendAttributes(StringBuilder buffer, Address startAddr, Address endAddr) {
		AddressSpace space = startAddr.getAddressSpace();
		long offset = startAddr.getOffset();
		long size = endAddr.getOffset() - offset + 1;

		if (space != endAddr.getAddressSpace()) {
			throw new IllegalArgumentException(
				"Range boundaries are not in the same address space");
		}
		if (size < 0) {
			throw new IllegalArgumentException("Start of range comes after end of range");
		}

		long last = offset + size - 1;
		boolean useFirst = (offset != 0);
		boolean useLast = (last != -1);
		SpecXmlUtils.encodeStringAttribute(buffer, "space", space.getName());
		if (useFirst) {
			SpecXmlUtils.encodeUnsignedIntegerAttribute(buffer, "first", offset);
		}
		if (useLast) {
			SpecXmlUtils.encodeUnsignedIntegerAttribute(buffer, "last", last);
		}
	}

	/**
	 * Write out the given Address as an \<addr> tag to the XML stream
	 * 
	 * @param buf is the XML stream
	 * @param addr -- Address to convert to XML
	 */
	public static void buildXML(StringBuilder buf, Address addr) {

		if ((addr == null) || (addr == Address.NO_ADDRESS)) {
			buf.append("<addr/>");
			return;
		}
		buf.append("<addr");
		AddressXML.appendAttributes(buf, addr);
		buf.append("/>");
	}

	/**
	 * Write out the given Address and a size as an \<addr> tag to the XML stream
	 * 
	 * @param buf is the XML stream
	 * @param addr is the given Address
	 * @param size is the given size
	 */
	public static void buildXML(StringBuilder buf, Address addr, int size) {
		buf.append("<addr");
		AddressXML.appendAttributes(buf, addr, size);
		buf.append("/>");
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

	/**
	 * Write out a sequence of Varnodes as a single \<addr> tag to an XML stream.
	 * If there is more than one Varnode, or if the logical size is non-zero,
	 * the \<addr> tag will specify the address space as "join" and will have
	 * additional "piece" attributes.
	 * 
	 * @param buf is the XML stream
	 * @param varnodes is the sequence of storage varnodes
	 * @param logicalsize is the logical size value of the varnode
	 */
	public static void buildXML(StringBuilder buf, Varnode[] varnodes, long logicalsize) {

		if (varnodes == null) {
			buf.append("<addr/>");
			return;
		}
		if ((varnodes.length == 1) && (logicalsize == 0)) {
			AddressXML.buildXML(buf, varnodes[0].getAddress(), varnodes[0].getSize());
			return;
		}
		buf.append("<addr space=\"join\"");
		int piece = 0;
		for (Varnode vn : varnodes) {
			buf.append(" piece");
			buf.append(Integer.toString(++piece));
			buf.append("=\"");
			buildVarnodePiece(buf, vn.getAddress(), vn.getSize());
			buf.append("\"");
		}
		if (logicalsize != 0) {
			buf.append(" logicalsize=\"").append(logicalsize).append('\"');
		}
		buf.append("/>");
	}
}
