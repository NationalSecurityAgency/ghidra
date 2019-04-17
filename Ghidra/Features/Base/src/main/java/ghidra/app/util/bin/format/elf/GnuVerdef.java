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
package ghidra.app.util.bin.format.elf;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

/**
 * Version definition sections.
 * <pre>
 * typedef struct {
 *   Elf32_Half	vd_version;		//Version revision
 *   Elf32_Half	vd_flags;		//Version information
 *   Elf32_Half	vd_ndx;			//Version Index
 *   Elf32_Half	vd_cnt;			//Number of associated aux entries
 *   Elf32_Word	vd_hash;		//Version name hash value
 *   Elf32_Word	vd_aux;			//Offset in bytes to verdaux array
 *   Elf32_Word	vd_next;		//Offset in bytes to next verdef entry
 * } Elf32_Verdef;
 * 
 * typedef struct {
 *   Elf64_Half	vd_version;		//Version revision
 *   Elf64_Half	vd_flags;		//Version information
 *   Elf64_Half	vd_ndx;			//Version Index
 *   Elf64_Half	vd_cnt;			//Number of associated aux entries
 *   Elf64_Word	vd_hash;		//Version name hash value
 *   Elf64_Word	vd_aux;			//Offset in bytes to verdaux array
 *   Elf64_Word	vd_next;		//Offset in bytes to next verdef entry
 * } Elf64_Verdef;
 * 
 * </pre>
 */
public class GnuVerdef implements StructConverter {
    private short vd_version;
    private short vd_flags;
    private short vd_ndx;
    private short vd_cnt;
    private int   vd_hash;
    private int   vd_aux;
    private int   vd_next;

    GnuVerdef(BinaryReader reader) throws IOException {
        vd_version = reader.readNextShort();
        vd_flags   = reader.readNextShort();
        vd_ndx     = reader.readNextShort();
        vd_cnt     = reader.readNextShort();
        vd_hash    = reader.readNextInt();
        vd_aux     = reader.readNextInt();
        vd_next    = reader.readNextInt();
    }

    public short getVersion() {
		return vd_version;
	}
    public short getFlags() {
		return vd_flags;
	}
    public short getNdx() {
		return vd_ndx;
	}
    public short getCnt() {
		return vd_cnt;
	}
    public int getHash() {
		return vd_hash;
	}
    public int getAux() {
		return vd_aux;
	}
    public int getNext() {
		return vd_next;
	}

    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    public DataType toDataType() throws DuplicateNameException, IOException {
        StructureDataType struct = new StructureDataType("Elf_Verdef", 0);
        struct.add( WORD, "vd_version", "Version revision");
        struct.add( WORD, "vd_flags",   "Version information");
        struct.add( WORD, "vd_ndx",     "Version Index");
        struct.add( WORD, "vd_cnt",     "Number of associated aux entries");
        struct.add(DWORD, "vd_hash",    "Version name hash value");
        struct.add(DWORD, "vd_aux",     "Offset in bytes to verdaux array");
        struct.add(DWORD, "vd_next",    "Offset in bytes to next verdef entry");
        return struct;
    }

}
