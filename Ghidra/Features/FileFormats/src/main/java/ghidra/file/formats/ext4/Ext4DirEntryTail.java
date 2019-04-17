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

public class Ext4DirEntryTail implements StructConverter {

	private int det_reserved_zero1;
	private short det_rec_len;
	private byte det_reserved_zero2;
	private byte det_reserved_ft;
	private int det_checksum;
	
	public Ext4DirEntryTail(ByteProvider provider) throws IOException {
		this( new BinaryReader( provider, true ) );
	}
	
	public Ext4DirEntryTail(BinaryReader reader) throws IOException {
		det_reserved_zero1 = reader.readNextInt();
		det_rec_len = reader.readNextShort();
		det_reserved_zero2 = reader.readNextByte();
		det_reserved_ft = reader.readNextByte();
		det_checksum = reader.readNextInt();
	}
	
	public int getDet_reserved_zero1() {
		return det_reserved_zero1;
	}

	public short getDet_rec_len() {
		return det_rec_len;
	}

	public byte getDet_reserved_zero2() {
		return det_reserved_zero2;
	}

	public byte getDet_reserved_ft() {
		return det_reserved_ft;
	}

	public int getDet_checksum() {
		return det_checksum;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("ext4_dir_entry_tail", 0);
		structure.add(DWORD, "det_reserved_zero1", null);
		structure.add(WORD, "det_rec_len", null);
		structure.add(BYTE, "det_reserved_zero2", null);
		structure.add(BYTE, "det_reserved_ft", null);
		structure.add(DWORD, "det_checksum", null);
		return structure;
	}

}
