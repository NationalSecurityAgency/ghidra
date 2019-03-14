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
class S_LABEL32 extends DebugSymbol {
    private byte flags;
	
    static S_LABEL32 createS_LABEL32(short length, short type,
            FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
        S_LABEL32 s_label32 = (S_LABEL32) reader.getFactory().create(S_LABEL32.class);
        s_label32.initS_LABEL32(length, type, reader, ptr);
        return s_label32;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public S_LABEL32() {}

    private void initS_LABEL32(short length, short type, FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
		processDebugSymbol(length, type);
		
		offset  = reader.readInt(ptr);   ptr += BinaryReader.SIZEOF_INT;
		section = reader.readShort(ptr); ptr += BinaryReader.SIZEOF_SHORT;
		flags   = reader.readByte(ptr);  ptr += BinaryReader.SIZEOF_BYTE;
		
		byte nameLen = reader.readByte(ptr); ptr += BinaryReader.SIZEOF_BYTE;
		name = reader.readAsciiString(ptr, Conv.byteToInt(nameLen)); 
		Msg.debug(this, "Created label symbol: " +name);
		
	}
	/**
	 * @return the flags of this S_LABEL32 symbol
	 */
	byte getFlags() {
		return flags;
	}

}
