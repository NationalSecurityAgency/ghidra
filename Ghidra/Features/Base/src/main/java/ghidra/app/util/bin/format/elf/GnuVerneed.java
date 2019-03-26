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
 * Version dependency section.
 * <pre>
 * typedef struct {
 *   Elf32_Half	vn_version;		//Version of structure
 *   Elf32_Half	vn_cnt;			//Number of associated aux entries
 *   Elf32_Word	vn_file;		//Offset of filename for this dependency
 *   Elf32_Word	vn_aux;			//Offset in bytes to vernaux array
 *   Elf32_Word	vn_next;		//Offset in bytes to next verneed entry
 * } Elf32_Verneed;
 * 
 * typedef struct {
 *   Elf64_Half	vn_version;		//Version of structure
 *   Elf64_Half	vn_cnt;			//Number of associated aux entries
 *   Elf64_Word	vn_file;		//Offset of filename for this dependency
 *   Elf64_Word	vn_aux;			//Offset in bytes to vernaux array
 *   Elf64_Word	vn_next;		//Offset in bytes to next verneed entry
 * } Elf64_Verneed;
 * 
 * </pre>
 */
public class GnuVerneed implements StructConverter {
    private short vn_version;
    private short vn_cnt;
    private int   vn_file;
    private int   vn_aux;
    private int   vn_next;

    GnuVerneed(BinaryReader reader) throws IOException {
        vn_version = reader.readNextShort();
        vn_cnt     = reader.readNextShort();
        vn_file    = reader.readNextInt();
        vn_aux     = reader.readNextInt();
        vn_next    = reader.readNextInt();
    }

    public short getVersion() {
		return vn_version;
	}
    public short getCnt() {
		return vn_cnt;
	}
    public int getFile() {
		return vn_file;
	}
    public int getAux() {
		return vn_aux;
	}
    public int getNext() {
		return vn_next;
	}

    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    public DataType toDataType() throws DuplicateNameException, IOException {
        StructureDataType struct = new StructureDataType("Elf_Verneed", 0);
        struct.add( WORD, "vd_version", "Version of structure");
        struct.add( WORD, "vd_cnt",     "Number of associated aux entries");
        struct.add(DWORD, "vn_file",    "Offset of filename for this dependency");
        struct.add(DWORD, "vd_aux",     "Offset in bytes to vernaux array");
        struct.add(DWORD, "vd_next",    "Offset in bytes to next verneed entry");
        return struct;
    }
}
