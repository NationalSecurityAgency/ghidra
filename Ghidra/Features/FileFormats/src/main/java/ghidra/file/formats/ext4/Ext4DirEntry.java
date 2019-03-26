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

public class Ext4DirEntry implements StructConverter {
	
	private int inode;
	private short rec_len;
	private short name_len;
	private String name;
	private byte[] extra;

	public Ext4DirEntry( ByteProvider provider ) throws IOException {
		this( new BinaryReader( provider, true) );
	}
	
	public Ext4DirEntry( BinaryReader reader ) throws IOException {
		inode = reader.readNextInt();
		rec_len = reader.readNextShort();
		name_len = reader.readNextShort();
		name = reader.readNextAsciiString(name_len);
		
		int extraSize = rec_len - (8 + name_len);
		if( extraSize > 0 ) {
			extra = reader.readNextByteArray(extraSize);
		}
	}
	
	public int getInode() {
		return inode;
	}

	public short getRec_len() {
		return rec_len;
	}

	public short getName_len() {
		return name_len;
	}

	public String getName() {
		return name;
	}
	
	public byte[] getExtra() {
		return extra;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("ext4_dir_entry", 0);
		structure.add(DWORD, "inode", null);
		structure.add(WORD, "rec_len", null);
		structure.add(WORD, "name_len", null);
		structure.add(STRING, name_len, "name", null);
		if( extra != null ) {
			structure.add( new ArrayDataType(BYTE, extra.length, BYTE.getLength()), "extra", null);
		}
		return structure;
	}

}
