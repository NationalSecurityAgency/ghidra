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

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class Ext4DirEntry implements StructConverter {
	protected static final int SIZEOF_FIXEDFIELDS = 8;
	
	protected int inode;
	protected short rec_len;
	protected short name_len;
	protected String name;
	protected byte[] extra;

	/**
	 * Reads a Ext4DirEntry from the stream.
	 * 
	 * @param reader BinaryReader to read from
	 * @return new Ext4DirEntry, or null if eof
	 * @throws IOException if error when reading
	 */
	public static Ext4DirEntry read(BinaryReader reader) throws IOException {
		if (reader.getPointerIndex() + SIZEOF_FIXEDFIELDS >= reader.length()) {
			return null;
		}
		Ext4DirEntry result = new Ext4DirEntry();
		result.inode = reader.readNextInt();
		result.rec_len = reader.readNextShort();
		result.name_len = reader.readNextShort();
		result.name = new String(reader.readNextByteArray(result.name_len), StandardCharsets.UTF_8);
		
		int extraSize =
			Short.toUnsignedInt(result.rec_len) - (SIZEOF_FIXEDFIELDS + result.name_len);
		if( extraSize > 0 ) {
			result.extra = reader.readNextByteArray(extraSize);
		}
		return result;
	}
	
	protected Ext4DirEntry() {
		// empty
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

	public boolean isUnused() {
		return inode == Ext4Constants.EXT4_INODE_INDEX_NULL;
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
