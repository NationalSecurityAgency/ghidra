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

public class Ext4DirEntry2 implements StructConverter {

	private int inode;
	private short rec_len;
	private byte name_len;
	private byte file_type;
	private String name;
	private byte[] extra;

	public Ext4DirEntry2( ByteProvider provider ) throws IOException {
		this( new BinaryReader( provider, true ) );
	}
	
	public Ext4DirEntry2( BinaryReader reader ) throws IOException {
		inode = reader.readNextInt( );
		rec_len = reader.readNextShort( );
		name_len = reader.readNextByte( );
		file_type = reader.readNextByte( );
		name = reader.readNextAsciiString( name_len & 0xff );
		
		int extraSize = ( rec_len & 0xffff ) - ( 8 + ( name_len & 0xff ) );
		if ( extraSize > 0 ) {
			extra = reader.readNextByteArray( extraSize );
		}
	}
	
	public int getInode() {
		return inode;
	}

	public short getRec_len() {
		return rec_len;
	}

	public byte getName_len() {
		return name_len;
	}

	public byte getFile_type() {
		return file_type;
	}

	public String getName() {
		return name;
	}
	
	public byte[] getExtra() {
		return extra;
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
