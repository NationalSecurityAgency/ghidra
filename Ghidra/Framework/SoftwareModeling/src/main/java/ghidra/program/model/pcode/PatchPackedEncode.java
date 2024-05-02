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

public class PatchPackedEncode extends PackedEncode implements PatchEncoder {

	private PackedBytes editStream;

	public PatchPackedEncode() {
		editStream = null;
	}

	@Override
	public int size() {
		return editStream.size();
	}

	@Override
	public void writeSpaceId(AttributeId attribId, long spaceId) throws IOException {
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
		int val = editStream.getByte(pos) & (HEADER_MASK | HEADEREXTEND_MASK);
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
			res |= (editStream.getByte(pos) & RAWDATA_MASK);
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
			int header1 = editStream.getByte(pos);	// Attribute header
			if ((header1 & HEADER_MASK) != ATTRIBUTE) {
				return false;
			}
			pos += 1;
			int curid = header1 & ELEMENTID_MASK;
			if ((header1 & HEADEREXTEND_MASK) != 0) {
				curid <<= RAWDATA_BITSPERBYTE;
				curid |= editStream.getByte(pos) & RAWDATA_MASK;
				pos += 1;				// Extra byte for extended id
			}
			typeByte = editStream.getByte(pos) & 0xff;	// Type (and length) byte
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
			editStream.insertByte(pos, (int) piece);
			pos += 1;
		}
		return true;
	}

	@Override
	public void clear() {
		editStream = new PackedBytes(512);
		outStream = editStream;
	}

	@Override
	public boolean isEmpty() {
		return (editStream.size() == 0);
	}

	@Override
	public void writeTo(OutputStream stream) throws IOException {
		editStream.writeTo(stream);
	}

}
