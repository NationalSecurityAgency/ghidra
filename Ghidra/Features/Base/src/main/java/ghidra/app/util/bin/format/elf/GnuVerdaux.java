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
 * Auxiliary version information.
 * <pre>
 * typedef struct {
 *   Elf32_Word	vda_name;		//Version or dependency names
 *   Elf32_Word	vda_next;		//Offset in bytes to next verdaux entry
 * } Elf32_Verdaux;
 * 
 * typedef struct {
 *   Elf64_Word	vda_name;		//Version or dependency names
 *   Elf64_Word	vda_next;		//Offset in bytes to next verdaux entry
 * } Elf32_Verdaux;
 * 
 * </pre>
 */
public class GnuVerdaux implements StructConverter {
    private int vda_name;
    private int vda_next;

    GnuVerdaux(BinaryReader reader) throws IOException {
        vda_name   = reader.readNextInt();
        vda_next   = reader.readNextInt();
    }

    public int getVda_name() {
		return vda_name;
	}
    public int getVda_next() {
		return vda_next;
	}

    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    public DataType toDataType() throws DuplicateNameException, IOException {
        StructureDataType struct = new StructureDataType("Elf_Verdaux", 0);
        struct.add(DWORD, "vna_name",  "Version or dependency names");
        struct.add(DWORD, "vna_next",  "Offset in bytes to next verdaux entry");
        return struct;
    }
}
