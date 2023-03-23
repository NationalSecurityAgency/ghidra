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

import static ghidra.program.model.pcode.PackedDecode.*;

import java.io.IOException;
import java.io.OutputStream;

import ghidra.program.model.address.AddressSpace;

/**
 * A byte-based encoder designed to marshal to the decompiler efficiently
 * See {@code PackedDecode} for details of the encoding format
 */
public class PackedEncode implements PatchEncoder {
	private PackedBytes outStream;

	private void writeHeader(int header, int id) {
		if (id > 0x1f) {
			header |= HEADEREXTEND_MASK;
			header |= (id >> RAWDATA_BITSPERBYTE);
			int extendByte = (id & RAWDATA_MASK) | RAWDATA_MARKER;
			outStream.write(header);
			outStream.write(extendByte);
		}
		else {
			header |= id;
			outStream.write(header);
		}
	}

	private void writeInteger(int typeByte, long val) {
		byte lenCode;
		int sa;
		if (val <= 0) {
			if (val == 0) {
				lenCode = 0;
				sa = -1;
			}
			else {
				lenCode = 10;
				sa = 9 * RAWDATA_BITSPERBYTE;
			}
		}
		else if (val < 0x800000000L) {
			if (val < 0x200000L) {
				if (val < 0x80L) {
					lenCode = 1;		// 7-bits
					sa = 0;
				}
				else if (val < 0x4000L) {
					lenCode = 2;		// 14-bits
					sa = RAWDATA_BITSPERBYTE;
				}
				else {
					lenCode = 3;		// 21-bits
					sa = 2 * RAWDATA_BITSPERBYTE;
				}
			}
			else if (val < 0x10000000L) {
				lenCode = 4;		// 28-bits
				sa = 3 * RAWDATA_BITSPERBYTE;
			}
			else {
				lenCode = 5;		// 35-bits
				sa = 4 * RAWDATA_BITSPERBYTE;
			}
		}
		else if (val < 0x2000000000000L) {
			if (val < 0x40000000000L) {
				lenCode = 6;
				sa = 5 * RAWDATA_BITSPERBYTE;
			}
			else {
				lenCode = 7;
				sa = 6 * RAWDATA_BITSPERBYTE;
			}
		}
		else {
			if (val < 0x100000000000000L) {
				lenCode = 8;
				sa = 7 * RAWDATA_BITSPERBYTE;
			}
			else {
				lenCode = 9;
				sa = 8 * RAWDATA_BITSPERBYTE;
			}
		}
		typeByte |= lenCode;
		outStream.write(typeByte);
		for (; sa >= 0; sa -= RAWDATA_BITSPERBYTE) {
			long piece = (val >>> sa) & RAWDATA_MASK;
			piece |= RAWDATA_MARKER;
			outStream.write((int) piece);
		}
	}

	public PackedEncode() {
		outStream = null;
	}

	@Override
	public void clear() {
		outStream = new PackedBytes(512);
	}

	@Override
	public void openElement(ElementId elemId) throws IOException {
		writeHeader(ELEMENT_START, elemId.id());
	}

	@Override
	public void closeElement(ElementId elemId) throws IOException {
		writeHeader(ELEMENT_END, elemId.id());
	}

	@Override
	public void writeBool(AttributeId attribId, boolean val) throws IOException {
		writeHeader(ATTRIBUTE, attribId.id());
		int typeByte = val ? 0x11 : 0x10;
		outStream.write(typeByte);
	}

	@Override
	public void writeSignedInteger(AttributeId attribId, long val) throws IOException {
		writeHeader(0xc0, attribId.id());
		int typeByte;
		long num;
		if (val < 0) {
			typeByte = (TYPECODE_SIGNEDINT_NEGATIVE << TYPECODE_SHIFT);
			num = -val;
		}
		else {
			typeByte = (TYPECODE_SIGNEDINT_POSITIVE << TYPECODE_SHIFT);
			num = val;
		}
		writeInteger(typeByte, num);
	}

	@Override
	public void writeUnsignedInteger(AttributeId attribId, long val) throws IOException {
		writeHeader(ATTRIBUTE, attribId.id());
		writeInteger((TYPECODE_UNSIGNEDINT << TYPECODE_SHIFT), val);
	}

	@Override
	public void writeString(AttributeId attribId, String val) throws IOException {
		byte[] bytes = val.getBytes();
		writeHeader(ATTRIBUTE, attribId.id());
		writeInteger((TYPECODE_STRING << TYPECODE_SHIFT), bytes.length);
		outStream.write(bytes);
	}

	@Override
	public void writeStringIndexed(AttributeId attribId, int index, String val) throws IOException {
		byte[] bytes = val.getBytes();
		writeHeader(ATTRIBUTE, attribId.id() + index);
		writeInteger((TYPECODE_STRING << TYPECODE_SHIFT), bytes.length);
		outStream.write(bytes);
	}

	@Override
	public void writeSpace(AttributeId attribId, AddressSpace spc) throws IOException {
		writeHeader(ATTRIBUTE, attribId.id());
		switch (spc.getType()) {
			case AddressSpace.TYPE_CONSTANT:
			case AddressSpace.TYPE_RAM:
			case AddressSpace.TYPE_REGISTER:
			case AddressSpace.TYPE_UNIQUE:
			case AddressSpace.TYPE_OTHER:
				writeInteger((TYPECODE_ADDRESSSPACE << TYPECODE_SHIFT), spc.getUnique());
				break;
			case AddressSpace.TYPE_VARIABLE:
				outStream.write((TYPECODE_SPECIALSPACE << TYPECODE_SHIFT) | SPECIALSPACE_JOIN);
				break;
			case AddressSpace.TYPE_STACK:
				outStream.write((TYPECODE_SPECIALSPACE << TYPECODE_SHIFT) | SPECIALSPACE_STACK);
				break;
			default:
				throw new IOException("Cannot marshal address space: " + spc.getName());
		}
	}

	@Override
	public void writeTo(OutputStream stream) throws IOException {
		outStream.writeTo(stream);
	}

	@Override
	public boolean isEmpty() {
		return (outStream.size() == 0);
	}

	@Override
	public int size() {
		return outStream.size();
	}

	@Override
	public void writeSpaceId(AttributeId attribId, long spaceId) {
		writeHeader(ATTRIBUTE, attribId.id());
		int uniqueId = (int) spaceId >> AddressSpace.ID_UNIQUE_SHIFT;
		writeInteger((TYPECODE_ADDRESSSPACE << TYPECODE_SHIFT), uniqueId);
	}

	/**
	 * Return the position after the open element directive at the given position.
	 * @param pos is the given position
	 * @return the next position or -1 if the current byte is not an open directive
	 */
	private int skipOpen(int pos) {
		int val = outStream.getByte(pos) & (HEADER_MASK | HEADEREXTEND_MASK);
		if (val == ELEMENT_START) {
			return pos + 1;
		}
		else if (val == (ELEMENT_START | HEADEREXTEND_MASK)) {
			return pos + 2;
		}
		return -1;
	}

	/**
	 * Read the integer at the given position.
	 * @param pos is the given position
	 * @param len is the length of the integer in 7-bit bytes
	 * @return the integer
	 */
	private long readInteger(int pos, int len) {
		long res = 0;
		while (len > 0) {
			res <<= RAWDATA_BITSPERBYTE;
			res |= (outStream.getByte(pos) & RAWDATA_MASK);
			pos += 1;
			len -= 1;
		}
		return res;
	}

	@Override
	public boolean patchIntegerAttribute(int pos, AttributeId attribId, long val) {
		int typeByte;
		int length;

		pos = skipOpen(pos);
		if (pos < 0) {
			return false;
		}
		for (;;) {
			int header1 = outStream.getByte(pos);	// Attribute header
			if ((header1 & HEADER_MASK) != ATTRIBUTE) {
				return false;
			}
			pos += 1;
			int curid = header1 & ELEMENTID_MASK;
			if ((header1 & HEADEREXTEND_MASK) != 0) {
				curid <<= RAWDATA_BITSPERBYTE;
				curid |= outStream.getByte(pos) & RAWDATA_MASK;
				pos += 1;				// Extra byte for extended id
			}
			typeByte = outStream.getByte(pos) & 0xff;	// Type (and length) byte
			pos += 1;
			int attribType = typeByte >> TYPECODE_SHIFT;
			if (attribType == TYPECODE_BOOLEAN || attribType == TYPECODE_SPECIALSPACE) {
				continue;								// has no additional data
			}
			length = typeByte & LENGTHCODE_MASK;	// Length of data in bytes
			if (attribType == TYPECODE_STRING) {			// For a string
				length = (int) readInteger(pos, length);	// Read length field to get final length of string
			}
			if (attribId.id() == curid) {
				break;
			}
			pos += length;			// Skip -length- data	
		}
		if (length != 10) {
			return false;
		}

		for (int sa = 9 * RAWDATA_BITSPERBYTE; sa >= 0; sa -= RAWDATA_BITSPERBYTE) {
			long piece = (val >>> sa) & RAWDATA_MASK;
			piece |= RAWDATA_MARKER;
			outStream.insertByte(pos, (int) piece);
			pos += 1;
		}
		return true;
	}
}
