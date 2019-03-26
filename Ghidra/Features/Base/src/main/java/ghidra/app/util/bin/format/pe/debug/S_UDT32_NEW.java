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

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.*;
import ghidra.util.*;

import java.io.*;

/**
 * 
 */
class S_UDT32_NEW extends DebugSymbol {
    private int symType;

    static S_UDT32_NEW createS_UDT32_NEW(short length, short type,
            FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
        S_UDT32_NEW s_udt32_new = (S_UDT32_NEW) reader.getFactory().create(S_UDT32_NEW.class);
        s_udt32_new.initS_UDT32_NEW(length, type, reader, ptr);
        return s_udt32_new;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public S_UDT32_NEW() {}

	private void initS_UDT32_NEW(short length, short type, FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
		processDebugSymbol(length, type);

		symType = reader.readInt(ptr); ptr += BinaryReader.SIZEOF_INT;

		byte nameLen = reader.readByte(ptr); ptr += BinaryReader.SIZEOF_BYTE;

		name = reader.readAsciiString(ptr, Conv.byteToInt(nameLen));	
	}

	/**
	 * @return symType - the type of symbol
	 */
	int getSymType() {
		return symType;
	}

}
