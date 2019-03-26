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
package ghidra.file.formats.ext4;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class Ext4JournalHeaderS implements StructConverter {
	
	private int h_magic;
	private int h_blocktype;
	private int h_sequence;

	public Ext4JournalHeaderS(ByteProvider provider) throws IOException {
		this( new BinaryReader( provider, false ) );
	}
	
	public Ext4JournalHeaderS(BinaryReader reader) throws IOException {
		// Journal is big-endian... opposite of the rest of the file.
		reader.setLittleEndian(false);
		
		h_magic = reader.readNextInt();
		h_blocktype = reader.readNextInt();
		h_sequence = reader.readNextInt();
	}
	
	public int getH_magic() {
		return h_magic;
	}

	public int getH_blocktype() {
		return h_blocktype;
	}

	public int getH_sequence() {
		return h_sequence;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("journal_header_s", 0);
		structure.add(DWORD, "h_magic", null);
		structure.add(DWORD, "h_blocktype", null);
		structure.add(DWORD, "h_sequence", null);
		return structure;
	}

}
