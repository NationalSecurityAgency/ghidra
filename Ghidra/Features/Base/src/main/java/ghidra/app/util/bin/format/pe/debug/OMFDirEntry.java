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
 * typedef struct OMFDirEntry {
 *     unsigned short  SubSection;     // subsection type (sst...)
 *     unsigned short  iMod;           // module index
 *     long            lfo;            // large file offset of subsection
 *     unsigned long   cb;             // number of bytes in subsection
 * };
 * </pre>
 */
class OMFDirEntry {
    final static int IMAGE_SIZEOF_OMF_DIR_ENTRY = 12;

    private short subsection;
    private short imod;
    private int   lfo;
    private int   cb;

    static OMFDirEntry createOMFDirEntry(
            FactoryBundledWithBinaryReader reader, int index)
            throws IOException {
        OMFDirEntry omfDirEntry = (OMFDirEntry) reader.getFactory().create(OMFDirEntry.class);
        omfDirEntry.initOMFDirEntry(reader, index);
        return omfDirEntry;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public OMFDirEntry() {}

    private void initOMFDirEntry(FactoryBundledWithBinaryReader reader, int index) throws IOException {
        subsection = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;
        imod       = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;
        lfo        = reader.readInt  (index); index+=BinaryReader.SIZEOF_INT;
        cb         = reader.readInt  (index); index+=BinaryReader.SIZEOF_INT;
    }

    short getSubSectionType() {
        return subsection;
    }
    short getModuleIndex() {
        return imod;
    }
    int getLargeFileOffset() {
        return lfo;
    }
    int getNumberOfBytes() {
        return cb;
    }
}
