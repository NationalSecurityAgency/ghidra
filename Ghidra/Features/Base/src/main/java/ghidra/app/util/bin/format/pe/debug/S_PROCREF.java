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

class S_PROCREF extends DebugSymbol {
    private int module;
	private int checksum;
	private int paddingLen;

	S_PROCREF(short length, short type, BinaryReader reader, int ptr) throws IOException {
		processDebugSymbol(length, type);

//		if (type != DebugCodeViewConstants.S_PROCREF) {
//			throw new IllegalArgumentException("Incorrect type!");
//		}

		checksum = reader.readInt(ptr); ptr += BinaryReader.SIZEOF_INT;
		offset   = reader.readInt(ptr); ptr += BinaryReader.SIZEOF_INT;
		module   = reader.readInt(ptr); ptr += BinaryReader.SIZEOF_INT;

		if (checksum == 0) {
			byte nameLen = reader.readByte (ptr); ptr += BinaryReader.SIZEOF_BYTE;

			name = reader.readAsciiString(ptr, Byte.toUnsignedInt(nameLen));

			ptr += Byte.toUnsignedInt(nameLen);

			int val = ptr & 0xf; 

			switch (val) {
				case 0x1:
				case 0x2:
				case 0x3:
					paddingLen = 0x4 - val;
					break;
				case 0x5:
				case 0x6:
				case 0x7:
					paddingLen = 0x8 - val;
					break;
				case 0x9:
				case 0xa:
				case 0xb:
					paddingLen = 0xc - val;
					break;
				case 0xd:
				case 0xe:
				case 0xf:
					paddingLen = 0x10 - val;
					break;
			}

			ptr += paddingLen;
		} 
	}

	public int getModule() {
		return module;
	}
	public int getChecksum() {
		return checksum;
	}

	@Override
    public short getLength() {
		short len = super.getLength();
		if (checksum == 0) {
			 len += BinaryReader.SIZEOF_BYTE + name.length()+ paddingLen;
		}
		return len;
	}

}
