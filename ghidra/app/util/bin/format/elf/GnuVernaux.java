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
 * Auxiliary needed version information.
 * <pre>
 * typedef struct {
 *   Elf32_Word	vna_hash;		//Hash value of dependency name
 *   Elf32_Half	vna_flags;		//Dependency specific information
 *   Elf32_Half	vna_other;		//Unused
 *   Elf32_Word	vna_name;		//Dependency name string offset
 *   Elf32_Word	vna_next;		//Offset in bytes to next vernaux entry
 * } Elf32_Vernaux;
 *
 * typedef struct {
 *   Elf64_Word	vna_hash;		//Hash value of dependency name
 *   Elf64_Half	vna_flags;		//Dependency specific information
 *   Elf64_Half	vna_other;		//Unused
 *   Elf64_Word	vna_name;		//Dependency name string offset
 *   Elf64_Word	vna_next;		//Offset in bytes to next vernaux entry
 * } Elf64_Vernaux;
 *  
 * </pre>
 */
public class GnuVernaux implements StructConverter {
    private int   vna_hash;
    private short vna_flags;
    private short vna_other;
    private int   vna_name;
    private int   vna_next;

    GnuVernaux(BinaryReader reader) throws IOException {
        vna_hash  = reader.readNextInt();
        vna_flags = reader.readNextShort();
        vna_other = reader.readNextShort();
        vna_name  = reader.readNextInt();
        vna_next  = reader.readNextInt();
    }

    public int getHash() {
		return vna_hash;
	}
    public short getFlags() {
		return vna_flags;
	}
    public short getOther() {
		return vna_other;
	}
    public int getName() {
		return vna_name;
	}
    public int getNext() {
		return vna_next;
	}

    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    public DataType toDataType() throws DuplicateNameException, IOException {
        StructureDataType struct = new StructureDataType("Elf_Verdef", 0);
        struct.add(DWORD, "vna_hash",  "Hash value of dependency name");
        struct.add( WORD, "vna_flags", "Dependency specific information");
        struct.add( WORD, "vna_other", "Unused");
        struct.add(DWORD, "vna_name",  "Dependency name string offset");
        struct.add(DWORD, "vna_next",  "Offset in bytes to next vernaux entry");
        return struct;
    }
}
