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

public class Ext4DirEntry2 extends Ext4DirEntry implements StructConverter {
	protected byte file_type;

	/**
	 * Reads a Ext4DirEntry2 from the stream.
	 * 
	 * @param reader BinaryReader to read from
	 * @return new Ext4DirEntry2, or null if eof
	 * @throws IOException if error when reading
	 */
	public static Ext4DirEntry2 read(BinaryReader reader) throws IOException {
		if (reader.getPointerIndex() + 8 >= reader.length()) {
			return null;
		}
		Ext4DirEntry2 result = new Ext4DirEntry2();
		result.inode = reader.readNextInt();
		result.rec_len = reader.readNextShort();
		int uNameLen = reader.readNextUnsignedByte();
		result.name_len = (short) uNameLen;	// direntry2's only have a byte for name_len
		result.file_type = reader.readNextByte();
		result.name = new String(reader.readNextByteArray(uNameLen), StandardCharsets.UTF_8);

		int extraSize = Short.toUnsignedInt(result.rec_len) - (SIZEOF_FIXEDFIELDS + uNameLen);
		if (extraSize > 0) {
			result.extra = reader.readNextByteArray(extraSize);
		}

		return result;
	}

	private Ext4DirEntry2() {
		// nothing
	}

	public byte getFile_type() {
		return file_type;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String nameEnd = rec_len + "_" + (extra == null ? "0" : extra.length );
		Structure structure = new StructureDataType("ext4_dir_entry2_" + nameEnd, 0);
		structure.add(DWORD, "inode", null);
		structure.add(WORD, "rec_len", null);
		structure.add(BYTE, "name_len", null);
		structure.add(BYTE, "file_type", null);
		if ( ( name_len & 0xff ) > 0 ) {
			structure.add(STRING, ( name_len & 0xff ), "name", null);
		}
		if( extra != null ) {
			structure.add( new ArrayDataType(BYTE, extra.length, BYTE.getLength()), "extra", null);
		}
//		if ( structure.getLength() != ( rec_len & 0xffff ) ) {
//			System.out.println( "incorrect size!!" );
//		}
		return structure;
	}

}
