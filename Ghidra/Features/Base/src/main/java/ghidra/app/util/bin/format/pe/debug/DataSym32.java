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

import java.io.*;

/**
 * <pre>
 * typedef struct DATASYM32 {
 *     unsigned short  reclen;         // Record length
 *     unsigned short  rectyp;         // S_LDATA32, S_GDATA32 or S_PUB32
 *     CV_uoff32_t     off;            // (unsigned long)
 *     unsigned short  seg;
 *     CV_typ_t        typind;         // Type index (unsigned short)
 *     unsigned char   name[1];        // Length-prefixed name
 * } DATASYM32;
 * </pre>
 * 
 * 
 */
class DataSym32 extends DebugSymbol {
    private short   typeIndex;
    private byte    nameChar;

    static DataSym32 createDataSym32(short length, short type,
            FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
        DataSym32 dataSym32 = (DataSym32) reader.getFactory().create(DataSym32.class);
        dataSym32.initDataSym32(length, type, reader, ptr);
        return dataSym32;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public DataSym32() {}

    private void initDataSym32(short length, short type, FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
    	processDebugSymbol(length, type);

        this.offset    = reader.readInt  (ptr); ptr += BinaryReader.SIZEOF_INT;
        this.section   = reader.readShort(ptr); ptr += BinaryReader.SIZEOF_SHORT;
        this.typeIndex = reader.readShort(ptr); ptr += BinaryReader.SIZEOF_SHORT;
        this.nameChar  = reader.readByte (ptr); ptr += BinaryReader.SIZEOF_BYTE;
        this.name      = reader.readAsciiString(ptr); ptr += name.length();
    }

    int getTypeIndex() {
    	return typeIndex;
    }
    byte getNameChar() {
    	return nameChar;
    }
}
