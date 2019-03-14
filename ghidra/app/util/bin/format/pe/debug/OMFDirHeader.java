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

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.*;

import java.io.*;

/**
 * <pre>
 * typedef struct OMFDirHeader {
 *     unsigned short cbDirHeader; // length of this structure unsigned           
 *              short cbDirEntry;  // number of bytes in each directory entry 
 *     unsigned long  cDir;        // number of directorie entries 
 *              long lfoNextDir;   // offset from base of next directory 
 *     unsigned long flags;        // status flags
 * } OMFDirHeader;
 * </pre>
 * 
 * 
 */
class OMFDirHeader {
    final static int IMAGE_SIZEOF_OMF_DIR_HEADER = 16;

    private short cbDirHeader;
    private short cbDirEntry;
    private int   cDir;
    private int   lfoNextDir;
    private int   flags;

    static OMFDirHeader createOMFDirHeader(
            FactoryBundledWithBinaryReader reader, int index)
            throws IOException {
        OMFDirHeader omfDirHeader = (OMFDirHeader) reader.getFactory().create(OMFDirHeader.class);
        omfDirHeader.initOMFDirHeader(reader, index);
        return omfDirHeader;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public OMFDirHeader() {}

    private void initOMFDirHeader(FactoryBundledWithBinaryReader reader, int index) throws IOException {
        cbDirHeader = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;
        cbDirEntry  = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;
        cDir        = reader.readInt  (index); index+=BinaryReader.SIZEOF_INT;
        lfoNextDir  = reader.readInt  (index); index+=BinaryReader.SIZEOF_INT;
        flags       = reader.readInt  (index); index+=BinaryReader.SIZEOF_INT;
    }

    int getFlags() {
		return flags;
	}

    short getLengthInBytes() {
        return cbDirHeader;
    }
    short getNumberOfByteInEntries() {
        return cbDirEntry;
    }
    int getNumberOfEntries() {
        return cDir;
    }
    int getBaseOfNextEntry() {
        return lfoNextDir;
    }
}
