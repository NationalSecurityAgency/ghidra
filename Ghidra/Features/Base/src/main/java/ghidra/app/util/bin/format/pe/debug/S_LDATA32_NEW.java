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
package ghidra.app.util.bin.format.pe.debug;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Conv;

/**
 * 
 */
class S_LDATA32_NEW extends DebugSymbol{
    private int reserved;
	private byte [] padding;

	S_LDATA32_NEW(short length, short type, BinaryReader reader, int ptr) throws IOException {
		processDebugSymbol(length, type);
		reserved = reader.readInt  (ptr); ptr+=BinaryReader.SIZEOF_INT;
		offset   = reader.readInt  (ptr); ptr+=BinaryReader.SIZEOF_INT;
		section  = reader.readShort(ptr); ptr+=BinaryReader.SIZEOF_SHORT;

		byte nameLen = reader.readByte(ptr); ptr += BinaryReader.SIZEOF_BYTE;

		this.name = reader.readAsciiString(ptr, Conv.byteToInt(nameLen));
		ptr+=nameLen;

		int sizeOfPadding = Conv.shortToInt(length) - 
							BinaryReader.SIZEOF_SHORT - 
							BinaryReader.SIZEOF_INT - 
							BinaryReader.SIZEOF_INT - 
							BinaryReader.SIZEOF_SHORT - 
							BinaryReader.SIZEOF_BYTE - 
							Conv.byteToInt(nameLen);
		
		padding = reader.readByteArray(ptr, sizeOfPadding);
	}

	public int getReserved() {
		return reserved;
	}
	public byte [] getPadding() {
		return padding;
	}
}
