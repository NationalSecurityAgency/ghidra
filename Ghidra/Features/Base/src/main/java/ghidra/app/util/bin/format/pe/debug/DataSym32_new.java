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
 * <pre>
 * typedef struct DATASYM32_NEW {
 *     unsigned short  reclen;         // Record length
 *     unsigned short  rectyp;         // S_LDATA32, S_GDATA32 or S_PUB32
 *     CVTYPEINDEX     typind;
 *     unsigned long   off;
 *     unsigned short  seg;
 *     unsigned char   name[1];        // Length-prefixed name
 * } DATASYM32_NEW;
 * </pre>
 * 
 * 
 */
class DataSym32_new extends DebugSymbol {
    private int  typeIndex;
    private byte nameChar;

    static DataSym32_new createDataSym32_new(short length, short type,
            FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
        DataSym32_new dataSym32_new = (DataSym32_new) reader.getFactory().create(DataSym32_new.class);
        dataSym32_new.initDataSym32_new(length, type, reader, ptr);
        return dataSym32_new;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public DataSym32_new() {}

    private void initDataSym32_new(short length, short type, FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
    	processDebugSymbol(length, type);

        this.typeIndex = reader.readInt  (ptr); ptr += BinaryReader.SIZEOF_INT;
        this.offset    = reader.readInt  (ptr); ptr += BinaryReader.SIZEOF_INT;
        this.section   = reader.readShort(ptr); ptr += BinaryReader.SIZEOF_SHORT;

        byte nameLen = reader.readByte(ptr); ptr += BinaryReader.SIZEOF_BYTE;

        this.name = reader.readAsciiString(ptr, Conv.byteToInt(nameLen));
    }

    int getTypeIndex() {
    	return typeIndex;
    }
    byte getNameChar() {
    	return nameChar;
    }
}
