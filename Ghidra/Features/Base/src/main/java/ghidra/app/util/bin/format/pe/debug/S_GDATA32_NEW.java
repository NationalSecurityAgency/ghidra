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
import ghidra.util.Msg;

class S_GDATA32_NEW extends DebugSymbol {

	S_GDATA32_NEW(short length, short type, BinaryReader reader, int ptr) throws IOException {
		processDebugSymbol(length, type);

		int unknown = reader.readInt(ptr);
		ptr += BinaryReader.SIZEOF_INT;

		offset = reader.readInt(ptr);
		ptr += BinaryReader.SIZEOF_INT;
		section = reader.readShort(ptr);
		ptr += BinaryReader.SIZEOF_SHORT;

		byte nameLen = reader.readByte(ptr);
		ptr += BinaryReader.SIZEOF_BYTE;

		name = reader.readAsciiString(ptr, Conv.byteToInt(nameLen));

		Msg.debug(this, "S_DATA32_NEW: " + unknown);
	}

}
