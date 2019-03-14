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
class S_OBJNAME extends DebugSymbol {
    private int signature;
	private byte nameLen;
	private byte [] padding;
	
    static S_OBJNAME createS_OBJNAME(short length, short type,
            FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
        S_OBJNAME s_objname = (S_OBJNAME) reader.getFactory().create(S_OBJNAME.class);
        s_objname.initS_OBJNAME(length, type, reader, ptr);
        return s_objname;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public S_OBJNAME() {}

    private void initS_OBJNAME(short length, short type, FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
		processDebugSymbol(length, type);

		signature = reader.readInt(ptr);  ptr += BinaryReader.SIZEOF_INT;
		nameLen = reader.readByte(ptr); ptr += BinaryReader.SIZEOF_BYTE;
		name = reader.readAsciiString(ptr, Conv.byteToInt(nameLen)); ptr += nameLen + 1;

		int sizeOfPadding = BinaryReader.SIZEOF_SHORT+ 
							BinaryReader.SIZEOF_INT+
							BinaryReader.SIZEOF_INT+
							BinaryReader.SIZEOF_INT+
							BinaryReader.SIZEOF_BYTE+
							Conv.byteToInt(nameLen)+1;

		padding = reader.readByteArray(ptr, sizeOfPadding);
	}

	public int getSignature() {
		return signature;
	}
	public byte getNameLen() {
		return nameLen;
	}
	public byte [] getPadding() {
		return padding;
	}
}
