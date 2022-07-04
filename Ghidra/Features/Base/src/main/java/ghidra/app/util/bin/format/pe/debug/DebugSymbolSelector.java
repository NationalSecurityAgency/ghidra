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

/**
 * 
 */
public class DebugSymbolSelector {

	public static DebugSymbol selectSymbol(BinaryReader reader, int ptr) throws IOException {
		short length = reader.readShort(ptr); ptr+=BinaryReader.SIZEOF_SHORT;
		short type   = reader.readShort(ptr); ptr+=BinaryReader.SIZEOF_SHORT;

		if (length == 0 || type < 0) {
			return null;
		}

		switch (type) {
			case DebugCodeViewConstants.S_LDATA32:
			case DebugCodeViewConstants.S_GDATA32:
			case DebugCodeViewConstants.S_PUB32:
				return new DataSym32(length, type, reader, ptr);

			case DebugCodeViewConstants.S_PUBSYM32_NEW:
				return new DataSym32_new(length, type, reader, ptr);

			case DebugCodeViewConstants.S_PROCREF:
			case DebugCodeViewConstants.S_LPROCREF:
				return new S_PROCREF(length, type, reader, ptr);

			case DebugCodeViewConstants.S_DATAREF:
				return new S_DATAREF(length, type, reader, ptr);

			case DebugCodeViewConstants.S_ALIGN:
				return new S_ALIGN(length, type, reader, ptr);

			case DebugCodeViewConstants.S_UDT32:
				return new S_UDT32_NEW(length, type, reader, ptr);

			case DebugCodeViewConstants.S_LDATA32_NEW:
				return new S_LDATA32_NEW(length, type, reader, ptr);

			case DebugCodeViewConstants.S_LPROC32_NEW:
			case DebugCodeViewConstants.S_GPROC32_NEW:
				return new S_GPROC32_NEW(length, type, reader, ptr);

			case DebugCodeViewConstants.S_BPREL32_NEW:
				return new S_BPREL32_NEW(length, type, reader, ptr);

			case DebugCodeViewConstants.S_END:
				return new S_END(length, type, reader, ptr);

			case DebugCodeViewConstants.S_BLOCK32:
				return new S_BLOCK32(length, type);

			case DebugCodeViewConstants.S_COMPILE:
				return new S_COMPILE(length, type);

			case DebugCodeViewConstants.S_OBJNAME:
				return new S_OBJNAME(length, type, reader, ptr);

			case DebugCodeViewConstants.S_CONSTANT32:
				return new S_CONSTANT32(length, type, reader, ptr);

			case DebugCodeViewConstants.S_GDATA32_NEW:
				return new S_GDATA32_NEW(length, type, reader, ptr);
			
			case DebugCodeViewConstants.S_LABEL32:
				return new S_LABEL32(length, type, reader, ptr);
			
			default:
				return new UnknownSymbol(length, type, reader, ptr);
		}
	}
}

