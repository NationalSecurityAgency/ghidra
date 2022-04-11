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
class S_UDT32 extends DebugSymbol {
    private int checksum;
	private byte typeLen;
	
	S_UDT32(short length, short type, BinaryReader reader, int ptr) throws IOException {
		processDebugSymbol(length, type);

		if (type != DebugCodeViewConstants.S_UDT32) {
			throw new IllegalArgumentException("Incorrect type!");
		}

		this.checksum = reader.readInt(ptr);
		ptr += BinaryReader.SIZEOF_INT;
		this.typeLen = reader.readByte(ptr);
		ptr += BinaryReader.SIZEOF_BYTE;
		this.name = reader.readAsciiString(ptr, Conv.byteToInt(typeLen));
	}

	public int getChecksum() {
		return checksum;
	}
}
