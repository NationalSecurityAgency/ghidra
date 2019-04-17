/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
import ghidra.app.util.bin.format.*;

/**
 * 
 */
public class DebugSymbolSelector {

	public static DebugSymbol selectSymbol(FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
		short length = reader.readShort(ptr); ptr+=BinaryReader.SIZEOF_SHORT;
		short type   = reader.readShort(ptr); ptr+=BinaryReader.SIZEOF_SHORT;

		if (length == 0 || type < 0) {
			return null;
		}

		switch (type) {
			case DebugCodeViewConstants.S_LDATA32:
			case DebugCodeViewConstants.S_GDATA32:
			case DebugCodeViewConstants.S_PUB32:
				return DataSym32.createDataSym32(length, type, reader, ptr);                   

			case DebugCodeViewConstants.S_PUBSYM32_NEW:
				return DataSym32_new.createDataSym32_new(length, type, reader, ptr);

			case DebugCodeViewConstants.S_PROCREF:
			case DebugCodeViewConstants.S_LPROCREF:
				return S_PROCREF.createS_PROCREF(length, type, reader, ptr);

			case DebugCodeViewConstants.S_DATAREF:
				return S_DATAREF.createS_DATAREF(length, type, reader, ptr);

			case DebugCodeViewConstants.S_ALIGN:
				return S_ALIGN.createS_ALIGN(length, type, reader, ptr);

			case DebugCodeViewConstants.S_UDT32:
				return S_UDT32_NEW.createS_UDT32_NEW(length, type, reader, ptr);

			case DebugCodeViewConstants.S_LDATA32_NEW:
				return S_LDATA32_NEW.createS_LDATA32_NEW(length, type, reader, ptr);

			case DebugCodeViewConstants.S_LPROC32_NEW:
			case DebugCodeViewConstants.S_GPROC32_NEW:
				return S_GPROC32_NEW.createS_GPROC32_NEW(length, type, reader, ptr);

			case DebugCodeViewConstants.S_BPREL32_NEW:
				return S_BPREL32_NEW.createS_BPREL32_NEW(length, type, reader, ptr);

			case DebugCodeViewConstants.S_END:
				return S_END.createS_END(length, type, reader, ptr);

			case DebugCodeViewConstants.S_BLOCK32:
				return S_BLOCK32.createS_BLOCK32(length, type);

			case DebugCodeViewConstants.S_COMPILE:
				return S_COMPILE.createS_COMPILE(length, type);

			case DebugCodeViewConstants.S_OBJNAME:
				return S_OBJNAME.createS_OBJNAME(length, type, reader, ptr);

			case DebugCodeViewConstants.S_CONSTANT32:
				return S_CONSTANT32.createS_CONSTANT32(length, type, reader, ptr);

			case DebugCodeViewConstants.S_GDATA32_NEW:
				return S_GDATA32_NEW.createS_GDATA32_NEW(length, type, reader, ptr);
			
			case DebugCodeViewConstants.S_LABEL32:
				return S_LABEL32.createS_LABEL32(length, type, reader, ptr);
			
			default:
				return UnknownSymbol.createUnknownSymbol(length, type, reader, ptr);
		}
	}
}

