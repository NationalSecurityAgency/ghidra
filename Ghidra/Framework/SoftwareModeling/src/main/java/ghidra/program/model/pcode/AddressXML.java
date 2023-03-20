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
import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.exception.InvalidInputException;
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

	public static int MAX_PIECES = 64;	// Maximum pieces that can be marshaled in one join address
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
	 * Encode this sized address as an \<addr> element to the stream
	 * @param encoder is the stream encoder
	 * @throws IOException for errors in the underlying stream
	 */
	public void encode(Encoder encoder) throws IOException {
		if (joinRecord != null) {
			long logicalSize = size;
			long sizeSum = 0;
			for (Varnode vn : joinRecord) {
				sizeSum += vn.getSize();
			}
			if (sizeSum == size) {
				logicalSize = 0;
			}
			encode(encoder, joinRecord, logicalSize);
			return;
		}
		encoder.openElement(ELEM_ADDR);
		if (space != null) {
			encoder.writeSpace(ATTRIB_SPACE, space);
			encoder.writeUnsignedInteger(ATTRIB_OFFSET, offset);
			if (size != 0) {
				encoder.writeSignedInteger(ATTRIB_SIZE, size);
			}
		}
		encoder.closeElement(ELEM_ADDR);
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
	 * Create an address from "space" and "offset" attributes of the current element
	 * @param decoder is the stream decoder
	 * @return the decoded Address
	 * @throws DecoderException for any problems decoding the stream
	 */
	public static Address decodeFromAttributes(Decoder decoder) throws DecoderException {
		AddressSpace spc = null;
		long offset = -1;
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			if (attribId == ATTRIB_SPACE.id()) {
				spc = decoder.readSpace();
			}
			else if (attribId == ATTRIB_OFFSET.id()) {
				offset = decoder.readUnsignedInteger();
			}
		}
		if (spc == null) {
			return Address.NO_ADDRESS;
		}
		return spc.getAddress(offset);
	}

	/**
	 * Decode a VariableStorage object from the attributes in the current address element.
	 * The start of storage corresponds to the decoded address. The size is either passed
	 * in or is decoded from a size attribute.
	 * @param size is the desired size of storage or -1 to use the size attribute
	 * @param decoder is the stream decoder
	 * @param pcodeFactory is used to resolve address spaces, etc.
	 * @return the decoded VariableStorage
	 * @throws DecoderException for any errors in the encoding or problems creating the storage
	 */
	public static VariableStorage decodeStorageFromAttributes(int size, Decoder decoder,
			PcodeFactory pcodeFactory) throws DecoderException {
		VariableStorage storage;
		try {
			Address varAddr = decodeFromAttributes(decoder);
			AddressSpace spc = varAddr.getAddressSpace();
			if (spc == null || varAddr == Address.NO_ADDRESS) {
				storage = VariableStorage.VOID_STORAGE;
			}
			else if (spc.getType() != AddressSpace.TYPE_VARIABLE) {
				if (size <= 0) {
					size = (int) decoder.readSignedInteger(ATTRIB_SIZE);
				}
				Program program = pcodeFactory.getDataTypeManager().getProgram();
				storage = new VariableStorage(program, varAddr, size);
			}
			else {
				decoder.rewindAttributes();
				Varnode[] pieces = Varnode.decodePieces(decoder);
				storage = pcodeFactory.getJoinStorage(pieces);
			}
		}
		catch (InvalidInputException e) {
			throw new DecoderException("Invalid storage: " + e.getMessage());
		}
		return storage;
	}

	/**
	 * Create an address from a stream encoding. This recognizes elements
	 *   - \<addr>
	 *   - \<spaceid>
	 *   - \<iop> or
	 *   - any element with "space" and "offset" attributes
	 * 
	 * An empty \<addr> element, with no attributes, results in Address.NO_ADDRESS being returned.
	 * @param decoder is the stream decoder
	 * @return Address created from decode info
	 * @throws DecoderException for any problems decoding the stream
	 */
	public static Address decode(Decoder decoder) throws DecoderException {
		int el = decoder.openElement();
		if (el == ELEM_SPACEID.id()) {
			AddressSpace spc = decoder.readSpace(ATTRIB_NAME);
			decoder.closeElement(el);
			int spaceid = spc.getSpaceID();
			spc = decoder.getAddressFactory().getConstantSpace();
			return spc.getAddress(spaceid);
		}
		else if (el == ELEM_IOP.id()) {
			int ref = (int) decoder.readUnsignedInteger(ATTRIB_VALUE);
			decoder.closeElement(el);
			AddressSpace spc = decoder.getAddressFactory().getConstantSpace();
			return spc.getAddress(ref);
		}
		AddressSpace spc = null;
		long offset = -1;
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			if (attribId == ATTRIB_SPACE.id()) {
				spc = decoder.readSpace();
			}
			else if (attribId == ATTRIB_OFFSET.id()) {
				offset = decoder.readUnsignedInteger();
			}
		}
		decoder.closeElement(el);
		if (spc == null) {
			// EXTERNAL_SPACE is currently a placeholder for an unsupported decompiler address space
			return Address.NO_ADDRESS;
		}
		return spc.getAddress(offset);
	}

	/**
	 * Encode "space" and "offset" attributes for the current element, describing the
	 * given Address to the stream.
	 * @param encoder is the stream encoder
	 * @param addr is the given Address
	 * @throws IOException for errors in the underlying stream
	 */
	public static void encodeAttributes(Encoder encoder, Address addr) throws IOException {
		AddressSpace space = addr.getAddressSpace();
		encoder.writeSpace(ATTRIB_SPACE, space);
		encoder.writeUnsignedInteger(ATTRIB_OFFSET, addr.getUnsignedOffset());
	}

	/**
	 * Encode "space" "offset" and "size" attributes for the current element, describing
	 * the given memory range to the stream.
	 * @param encoder is the stream encoder
	 * @param addr is the starting Address of the memory range
	 * @param size is the size of the memory range
	 * @throws IOException for errors in the underlying stream
	 */
	public static void encodeAttributes(Encoder encoder, Address addr, int size)
			throws IOException {
		AddressSpace space = addr.getAddressSpace();

		encoder.writeSpace(ATTRIB_SPACE, space);
		encoder.writeUnsignedInteger(ATTRIB_OFFSET, addr.getUnsignedOffset());
		encoder.writeSignedInteger(ATTRIB_SIZE, size);
	}

	/**
	 * Encode a memory range, as "space", "first", and "last" attributes, for the current element,
	 * to the stream.
	 * @param encoder is the stream encoder
	 * @param startAddr is the first address in the range
	 * @param endAddr is the last address in the range
	 * @throws IOException for errors in the underlying stream
	 */
	public static void encodeAttributes(Encoder encoder, Address startAddr, Address endAddr)
			throws IOException {
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
		encoder.writeSpace(ATTRIB_SPACE, space);
		if (useFirst) {
			encoder.writeUnsignedInteger(ATTRIB_FIRST, offset);
		}
		if (useLast) {
			encoder.writeUnsignedInteger(ATTRIB_LAST, last);
		}
	}

	/**
	 * Encode the given Address as an \<addr> element to the stream
	 * 
	 * @param encoder is the stream encoder
	 * @param addr -- Address to encode
	 * @throws IOException for errors in the underlying stream
	 */
	public static void encode(Encoder encoder, Address addr) throws IOException {

		encoder.openElement(ELEM_ADDR);
		if ((addr == null) || (addr == Address.NO_ADDRESS)) {
			encoder.closeElement(ELEM_ADDR);
			return;
		}
		encodeAttributes(encoder, addr);
		encoder.closeElement(ELEM_ADDR);
	}

	/**
	 * Encode the given Address and a size as an \<addr> element to the stream
	 * 
	 * @param encoder is the stream encoder
	 * @param addr is the given Address
	 * @param size is the given size
	 * @throws IOException for errors in the underlying stream
	 */
	public static void encode(Encoder encoder, Address addr, int size) throws IOException {
		encoder.openElement(ELEM_ADDR);
		encodeAttributes(encoder, addr, size);
		encoder.closeElement(ELEM_ADDR);
	}

	/**
	 * Encode a sequence of Varnodes as a single \<addr> element to the stream.
	 * If there is more than one Varnode, or if the logical size is non-zero,
	 * the \<addr> element will specify the address space as "join" and will have
	 * additional "piece" attributes.
	 * 
	 * @param encoder is the stream encoder
	 * @param varnodes is the sequence of storage varnodes
	 * @param logicalsize is the logical size value of the varnode
	 * @throws IOException for errors in the underlying stream
	 */
	public static void encode(Encoder encoder, Varnode[] varnodes, long logicalsize)
			throws IOException {
		if (varnodes == null) {
			encoder.openElement(ELEM_ADDR);
			encoder.closeElement(ELEM_ADDR);
			return;
		}
		if ((varnodes.length == 1) && (logicalsize == 0)) {
			AddressXML.encode(encoder, varnodes[0].getAddress(), varnodes[0].getSize());
			return;
		}
		if (varnodes.length > MAX_PIECES) {
			throw new IOException("Exceeded maximum pieces in one join address");
		}
		encoder.openElement(ELEM_ADDR);
		encoder.writeSpace(ATTRIB_SPACE, AddressSpace.VARIABLE_SPACE);
		for (int i = 0; i < varnodes.length; ++i) {
			encoder.writeStringIndexed(ATTRIB_PIECE, i, varnodes[i].encodePiece());
		}
		if (logicalsize != 0) {
			encoder.writeUnsignedInteger(ATTRIB_LOGICALSIZE, logicalsize);
		}
		encoder.closeElement(ELEM_ADDR);
	}
}
