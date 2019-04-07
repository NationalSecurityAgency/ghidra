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
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class Ext4XattrHeader implements StructConverter {
	
	private int h_magic;
	private int h_refcount;
	private int h_blocks;
	private int h_hash;
	private int h_checksum;
	private int[] h_reserved; // 2 ints long
	
	public Ext4XattrHeader(ByteProvider provider) throws IOException {
		this( new BinaryReader( provider, true ) );
	}
	
	public Ext4XattrHeader(BinaryReader reader) throws IOException {
		h_magic = reader.readNextInt();
		h_refcount = reader.readNextInt();
		h_blocks = reader.readNextInt();
		h_hash = reader.readNextInt();
		h_checksum = reader.readNextInt();
		h_reserved = reader.readNextIntArray(2);
	}

	public int getH_magic() {
		return h_magic;
	}

	public int getH_refcount() {
		return h_refcount;
	}

	public int getH_blocks() {
		return h_blocks;
	}

	public int getH_hash() {
		return h_hash;
	}

	public int getH_checksum() {
		return h_checksum;
	}

	public int[] getH_reserved() {
		return h_reserved;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("ext4_xattr_header", 0);
		structure.add(DWORD, "h_magic", null);
		structure.add(DWORD, "h_refcount", null);
		structure.add(DWORD, "h_blocks", null);
		structure.add(DWORD, "h_hash", null);
		structure.add(DWORD, "h_checksum", null);
		structure.add( new ArrayDataType(DWORD, 2, DWORD.getLength()), "h_reserved", null);
		return structure;
	}

}
