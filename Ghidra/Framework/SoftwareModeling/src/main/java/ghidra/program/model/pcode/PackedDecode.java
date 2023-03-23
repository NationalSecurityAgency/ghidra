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
import java.io.InputStream;
import java.util.ArrayList;

import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;

/*
 * A byte-based decoder designed to marshal info to the decompiler efficiently
 * All bytes in the encoding are expected to be non-zero.  Element encoding looks like
 *    - 01xiiiii is an element start
 *    - 10xiiiii is an element end
 *    - 11xiiiii is an attribute start
 *
 * Where iiiii is the (first) 5 bits of the element/attribute id.
 * If x=0, the id is complete.  If x=1, the next byte contains 7 more bits of the id:  1iiiiiii
 * 
 *  After an attribute start, there follows a type byte:  ttttllll, where the first 4 bits indicate
 *  the type of attribute and final 4 bits are a "length code".  The types are:
 *    - 1 = boolean (lengthcode=0 for false, lengthcode=1 for true)
 *    - 2 = positive signed integer
 *    - 3 = negative signed integer (stored in negated form)
 *    - 4 = unsigned integer
 *    - 5 = basic address space (encoded as the integer index of the space)
 *    - 6 = special address space (lengthcode 0=>stack 1=>join 2=>fspec 3=>iop)
 *    - 7 = string
 *    
 * All attribute types except "boolean" and "special", have an encoded integer after the \e type byte.
 * The "length code", indicates the number bytes used to encode the integer,
 * 7-bits of info per byte, 1iiiiiii. A "length code" of 0 is used to encode and integer value
 * of 0, with no following bytes.
 * 
 * For strings, the integer encoded after the \e type byte, is the actual length of the string.  The
 * string data itself is stored immediately after the length integer using UTF8 format.
 * */
public class PackedDecode implements Decoder {

	public static final int HEADER_MASK = 0xc0;
	public static final int ELEMENT_START = 0x40;
	public static final int ELEMENT_END = 0x80;
	public static final int ATTRIBUTE = 0xc0;
	public static final int HEADEREXTEND_MASK = 0x20;
	public static final int ELEMENTID_MASK = 0x1f;
	public static final int RAWDATA_MASK = 0x7f;
	public static final int RAWDATA_BITSPERBYTE = 7;
	public static final int RAWDATA_MARKER = 0x80;
	public static final int TYPECODE_SHIFT = 4;
	public static final int LENGTHCODE_MASK = 0xf;
	public static final int TYPECODE_BOOLEAN = 1;
	public static final int TYPECODE_SIGNEDINT_POSITIVE = 2;
	public static final int TYPECODE_SIGNEDINT_NEGATIVE = 3;
	public static final int TYPECODE_UNSIGNEDINT = 4;
	public static final int TYPECODE_ADDRESSSPACE = 5;
	public static final int TYPECODE_SPECIALSPACE = 6;
	public static final int TYPECODE_STRING = 7;
	public static final int SPECIALSPACE_STACK = 0;
	public static final int SPECIALSPACE_JOIN = 1;
	public static final int SPECIALSPACE_FSPEC = 2;
	public static final int SPECIALSPACE_IOP = 3;
	public static final int SPECIALSPACE_SPACEBASE = 4;

	private AddressFactory addrFactory;
	protected AddressSpace[] spaces;
	private LinkedByteBuffer inStream;
	private LinkedByteBuffer.Position startPos;
	private LinkedByteBuffer.Position curPos;
	private LinkedByteBuffer.Position endPos;
	private boolean attributeRead;

	public PackedDecode(AddressFactory addrFactory) {
		this.addrFactory = addrFactory;
		inStream = null;
		startPos = new LinkedByteBuffer.Position();
		curPos = new LinkedByteBuffer.Position();
		endPos = new LinkedByteBuffer.Position();
		buildAddrSpaceArray();
	}

	private void buildAddrSpaceArray() {
		ArrayList<AddressSpace> spaceList = new ArrayList<>();
		AddressSpace[] allSpaces = addrFactory.getAllAddressSpaces();
		for (AddressSpace spc : allSpaces) {
			int type = spc.getType();
			if (type != AddressSpace.TYPE_CONSTANT && type != AddressSpace.TYPE_RAM &&
				type != AddressSpace.TYPE_REGISTER && type != AddressSpace.TYPE_UNIQUE &&
				type != AddressSpace.TYPE_OTHER) {
				continue;
			}
			int ind = spc.getUnique();
			while (spaceList.size() <= ind) {
				spaceList.add(null);
			}
			spaceList.set(ind, spc);
		}
		spaces = new AddressSpace[spaceList.size()];
		spaceList.toArray(spaces);
	}

	private long readInteger(int len) throws DecoderException {
		long res = 0;
		while (len > 0) {
			res <<= RAWDATA_BITSPERBYTE;
			res |= (curPos.getNextByte() & RAWDATA_MASK);
			len -= 1;
		}
		return res;
	}

	private void findMatchingAttribute(AttributeId attribId) throws DecoderException {
		curPos.copy(startPos);
		for (;;) {
			byte header1 = curPos.getByte();
			if ((header1 & HEADER_MASK) != ATTRIBUTE) {
				break;
			}
			int id = header1 & ELEMENTID_MASK;
			if ((header1 & HEADEREXTEND_MASK) != 0) {
				id <<= RAWDATA_BITSPERBYTE;
				id |= (curPos.getBytePlus1() & RAWDATA_MASK);
			}
			if (attribId.id() == id) {
				return;		// Found it
			}
			skipAttribute();
		}
		throw new DecoderException("Attribute " + attribId.name() + " is not present");
	}

	private void skipAttribute() throws DecoderException {
		byte header1 = curPos.getNextByte();	// Attribute header
		if ((header1 & HEADEREXTEND_MASK) != 0) {
			curPos.getNextByte();				// Extra byte for extended id
		}
		byte typeByte = curPos.getNextByte();	// Type (and length) byte
		int attribType = typeByte >> TYPECODE_SHIFT;
		if (attribType == TYPECODE_BOOLEAN || attribType == TYPECODE_SPECIALSPACE) {
			return;								// has no additional data
		}
		int length = typeByte & LENGTHCODE_MASK;			// Length of data in bytes
		if (attribType == TYPECODE_STRING) {				// For a string
			length = (int) readInteger(length);	// Read length field to get final length of string
		}
		curPos.advancePosition(length);			// Skip -length- data		
	}

	private void skipAttributeRemaining(byte typeByte) throws DecoderException {
		int attribType = typeByte >> TYPECODE_SHIFT;
		if (attribType == TYPECODE_BOOLEAN || attribType == TYPECODE_SPECIALSPACE) {
			return;								// has no additional data
		}
		int length = typeByte & LENGTHCODE_MASK;	// Length of data in bytes
		if (attribType == TYPECODE_STRING) {		// For a string
			length = (int) readInteger(length);	// Read length field to get final length of string
		}
		curPos.advancePosition(length);			// Skip -length- data			
	}

	@Override
	public AddressFactory getAddressFactory() {
		return addrFactory;
	}

	@Override
	public void clear() {
		inStream = null;
	}

	@Override
	public void open(int max, String source) {
		inStream = new LinkedByteBuffer(max, source);
	}

	@Override
	public void ingestStream(InputStream stream) throws IOException {
		inStream.ingestStream(stream);
	}

	@Override
	public void endIngest() {
		inStream.pad(ELEMENT_END);
		inStream.getStartPosition(endPos);
	}

	@Override
	public boolean isEmpty() {
		return (inStream == null);
	}

	@Override
	public int peekElement() throws DecoderException {
		byte header1 = endPos.getByte();
		if ((header1 & HEADER_MASK) != ELEMENT_START) {
			return 0;
		}
		int id = header1 & ELEMENTID_MASK;
		if ((header1 & HEADEREXTEND_MASK) != 0) {
			id <<= RAWDATA_BITSPERBYTE;
			id |= (endPos.getBytePlus1() & RAWDATA_MASK);
		}
		return id;
	}

	@Override
	public int openElement() throws DecoderException {
		byte header1 = endPos.getByte();
		if ((header1 & HEADER_MASK) != ELEMENT_START) {
			return 0;
		}
		endPos.getNextByte();
		int id = header1 & ELEMENTID_MASK;
		if ((header1 & HEADEREXTEND_MASK) != 0) {
			id <<= RAWDATA_BITSPERBYTE;
			id |= (endPos.getNextByte() & RAWDATA_MASK);
		}
		startPos.copy(endPos);
		curPos.copy(endPos);
		header1 = curPos.getByte();
		while ((header1 & HEADER_MASK) == ATTRIBUTE) {
			skipAttribute();
			header1 = curPos.getByte();
		}
		endPos.copy(curPos);
		curPos.copy(startPos);
		attributeRead = true;		// "Last attribute was read" is vacuously true
		return id;
	}

	@Override
	public int openElement(ElementId elemId) throws DecoderException {
		int id = openElement();
		if (id != elemId.id()) {
			if (id == 0) {
				throw new DecoderException(
					"Expecting <" + elemId.name() + "> but did not scan an element");
			}
			throw new DecoderException("Expecting <" + elemId.name() + "> but id did not match");
		}
		return id;
	}

	@Override
	public void closeElement(int id) throws DecoderException {
		byte header1 = endPos.getNextByte();
		if ((header1 & HEADER_MASK) != ELEMENT_END) {
			throw new DecoderException("Expecting element close");
		}
		int closeId = header1 & ELEMENTID_MASK;
		if ((header1 & HEADEREXTEND_MASK) != 0) {
			closeId <<= RAWDATA_BITSPERBYTE;
			closeId |= (endPos.getNextByte() & RAWDATA_MASK);
		}
		if (id != closeId) {
			throw new DecoderException("Did not see expected closing element");
		}
	}

	@Override
	public void closeElementSkipping(int id) throws DecoderException {
		ArrayList<Integer> idstack = new ArrayList<>();
		idstack.add(id);
		do {
			int header1 = endPos.getByte() & HEADER_MASK;
			if (header1 == ELEMENT_END) {
				int pos = idstack.size() - 1;
				closeElement(idstack.get(pos));
				idstack.remove(pos);
			}
			else if (header1 == ELEMENT_START) {
				idstack.add(openElement());
			}
			else {
				throw new DecoderException("Corrupt stream");
			}
		}
		while (!idstack.isEmpty());
	}

	@Override
	public int getNextAttributeId() throws DecoderException {
		if (!attributeRead) {
			skipAttribute();
		}
		byte header1 = curPos.getByte();
		if ((header1 & HEADER_MASK) != ATTRIBUTE) {
			return 0;
		}
		int id = header1 & ELEMENTID_MASK;
		if ((header1 & HEADEREXTEND_MASK) != 0) {
			id <<= RAWDATA_BITSPERBYTE;
			id |= (curPos.getBytePlus1() & RAWDATA_MASK);
		}
		attributeRead = false;
		return id;
	}

	@Override
	public int getIndexedAttributeId(AttributeId attribId) throws DecoderException {
		return AttributeId.ATTRIB_UNKNOWN.id();
	}

	@Override
	public void rewindAttributes() {
		curPos.copy(startPos);
		attributeRead = true;
	}

	@Override
	public boolean readBool() throws DecoderException {
		byte header1 = curPos.getNextByte();
		if ((header1 & HEADEREXTEND_MASK) != 0) {
			curPos.getNextByte();
		}
		byte typeByte = curPos.getNextByte();
		if ((typeByte >> TYPECODE_SHIFT) != TYPECODE_BOOLEAN) {
			throw new DecoderException("Expecting boolean attribute");
		}
		attributeRead = true;
		return ((typeByte & LENGTHCODE_MASK) != 0);
	}

	@Override
	public boolean readBool(AttributeId attribId) throws DecoderException {
		findMatchingAttribute(attribId);
		boolean res = readBool();
		curPos.copy(startPos);
		return res;
	}

	@Override
	public long readSignedInteger() throws DecoderException {
		byte header1 = curPos.getNextByte();
		if ((header1 & HEADEREXTEND_MASK) != 0) {
			curPos.getNextByte();
		}
		byte typeByte = curPos.getNextByte();
		int typeCode = typeByte >> TYPECODE_SHIFT;
		long res;
		if (typeCode == TYPECODE_SIGNEDINT_POSITIVE) {
			res = readInteger(typeByte & LENGTHCODE_MASK);
		}
		else if (typeCode == TYPECODE_SIGNEDINT_NEGATIVE) {
			res = readInteger(typeByte & LENGTHCODE_MASK);
			res = -res;
		}
		else {
			skipAttributeRemaining(typeByte);
			throw new DecoderException("Expecting signed integer attribute");
		}
		attributeRead = true;
		return res;
	}

	@Override
	public long readSignedInteger(AttributeId attribId) throws DecoderException {
		findMatchingAttribute(attribId);
		long res = readSignedInteger();
		curPos.copy(startPos);
		return res;
	}

	@Override
	public long readSignedIntegerExpectString(String expect, long expectval)
			throws DecoderException {
		long res;
		LinkedByteBuffer.Position tmpPos = new LinkedByteBuffer.Position();
		tmpPos.copy(curPos);
		byte header1 = tmpPos.getNextByte();
		if ((header1 & HEADEREXTEND_MASK) != 0) {
			tmpPos.getNextByte();
		}
		byte typeByte = tmpPos.getNextByte();
		int typeCode = typeByte >> TYPECODE_SHIFT;
		if (typeCode == TYPECODE_STRING) {
			String val = readString();
			if (!val.equals(expect)) {
				throw new DecoderException(
					"Expecting string \"" + expect + "\" but read \"" + val + "\"");
			}
			res = expectval;
		}
		else {
			res = readSignedInteger();
		}
		return res;
	}

	@Override
	public long readSignedIntegerExpectString(AttributeId attribId, String expect, long expectval)
			throws DecoderException {
		findMatchingAttribute(attribId);
		long res = readSignedIntegerExpectString(expect, expectval);
		curPos.copy(startPos);
		return res;
	}

	@Override
	public long readUnsignedInteger() throws DecoderException {
		byte header1 = curPos.getNextByte();
		if ((header1 & HEADEREXTEND_MASK) != 0) {
			curPos.getNextByte();
		}
		byte typeByte = curPos.getNextByte();
		int typeCode = typeByte >> TYPECODE_SHIFT;
		long res;
		if (typeCode == TYPECODE_UNSIGNEDINT) {
			res = readInteger(typeByte & 0xf);
		}
		else {
			skipAttributeRemaining(typeByte);
			throw new DecoderException("Expecting unsigned integer attribute");
		}
		attributeRead = true;
		return res;
	}

	@Override
	public long readUnsignedInteger(AttributeId attribId) throws DecoderException {
		findMatchingAttribute(attribId);
		long res = readUnsignedInteger();
		curPos.copy(startPos);
		return res;
	}

	@Override
	public String readString() throws DecoderException {
		byte header1 = curPos.getNextByte();
		if ((header1 & HEADEREXTEND_MASK) != 0) {
			curPos.getNextByte();
		}
		byte typeByte = curPos.getNextByte();
		int typeCode = typeByte >> TYPECODE_SHIFT;
		if (typeCode != TYPECODE_STRING) {
			skipAttributeRemaining(typeByte);
			throw new DecoderException("Expecting string attribute");
		}
		int length = typeByte & LENGTHCODE_MASK;
		length = (int) readInteger(length);

		attributeRead = true;
		int curLen = curPos.array.length - curPos.current;
		if (curLen >= length) {
			String res = new String(curPos.array, curPos.current, length);
			curPos.advancePosition(length);
			return res;
		}
		StringBuilder buf = new StringBuilder();
		String res = new String(curPos.array, curPos.current, curLen);
		buf.append(res);
		length -= curLen;
		curPos.advancePosition(curLen);
		while (length > 0) {
			curLen = curPos.array.length - curPos.current;
			if (curLen > length) {
				curLen = length;
			}
			res = new String(curPos.array, curPos.current, curLen);
			buf.append(res);
			length -= curLen;
			curPos.advancePosition(curLen);
		}
		res = buf.toString();
		return res;
	}

	@Override
	public String readString(AttributeId attribId) throws DecoderException {
		findMatchingAttribute(attribId);
		String res = readString();
		curPos.copy(startPos);
		return res;
	}

	@Override
	public AddressSpace readSpace() throws DecoderException {
		byte header1 = curPos.getNextByte();
		if ((header1 & HEADEREXTEND_MASK) != 0) {
			curPos.getNextByte();
		}
		byte typeByte = curPos.getNextByte();
		int typeCode = typeByte >> TYPECODE_SHIFT;
		AddressSpace spc = null;
		if (typeCode == TYPECODE_ADDRESSSPACE) {
			int res = (int) readInteger(typeByte & LENGTHCODE_MASK);
			if (res >= 0 && res < spaces.length) {
				spc = spaces[res];
			}
			if (spc == null) {
				throw new DecoderException("Unknown address space index");
			}
		}
		else if (typeCode == TYPECODE_SPECIALSPACE) {
			int specialCode = typeByte & LENGTHCODE_MASK;
			if (specialCode == SPECIALSPACE_STACK) {
				spc = addrFactory.getStackSpace();
			}
			else if (specialCode == SPECIALSPACE_JOIN) {
				spc = AddressSpace.VARIABLE_SPACE;
			}
			else if (specialCode == SPECIALSPACE_SPACEBASE) {
				// TODO: Add support for decompiler non-stack "register relative" spaces
				// We let the null address space get returned here.  Its as if, no space
				// attribute is given in an <addr> element, resulting in NO_ADDRESS
				// spc = null;
			}
			else {
				throw new DecoderException("Cannot marshal special address space");
			}
		}
		else {
			skipAttributeRemaining(typeByte);
			throw new DecoderException("Expecting space attribute");
		}
		attributeRead = true;
		return spc;
	}

	@Override
	public AddressSpace readSpace(AttributeId attribId) throws DecoderException {
		findMatchingAttribute(attribId);
		AddressSpace res = readSpace();
		curPos.copy(startPos);
		return res;
	}

}
