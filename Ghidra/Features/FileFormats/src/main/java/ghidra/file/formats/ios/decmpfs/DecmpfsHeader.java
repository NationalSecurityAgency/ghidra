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
package ghidra.file.formats.ios.decmpfs;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.StringUtilities;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class DecmpfsHeader implements StructConverter {
	private int     compression_magic;
	private int     compression_type;
	private long    uncompressed_size;
	private byte [] attr_bytes;

	public DecmpfsHeader(BinaryReader reader, int size) throws IOException {
		long index = reader.getPointerIndex();

		this.compression_magic = reader.readNextInt();

		boolean originalEndian = reader.isLittleEndian();
		reader.setLittleEndian( true );

		this.compression_type  = reader.readNextInt();
		this.uncompressed_size = reader.readNextLong();

		reader.setLittleEndian( originalEndian );

		long endIndex = index + size + 1; //TODO always add 1????

		if ( ( endIndex % 2 ) != 0 ) {
			endIndex = endIndex - 1;
		}

		long nElements = endIndex - reader.getPointerIndex();

		this.attr_bytes = reader.readNextByteArray( (int)nElements );
	}

	public String getCompressionMagic() {
		return StringUtilities.toString( compression_magic );
	}

	public int getCompressionType() {
		return compression_type;
	}

	public long getUncompressedSize() {
		return uncompressed_size;
	}

	public byte [] getAttrBytes() {
		return attr_bytes;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = StructConverterUtil.parseName( DecmpfsHeader.class );
		Structure struct = new StructureDataType( name + "_" + attr_bytes.length, 0 );

		struct.add( STRING, 4, "compression_magic", null );
		struct.add( DWORD,     "compression_type",  null );
		struct.add( QWORD,     "uncompressed_size", null );

		if ( attr_bytes.length > 0 ) {
			ArrayDataType byteArrayDT = new ArrayDataType( BYTE , attr_bytes.length, BYTE.getLength() );
			struct.add( byteArrayDT, "attr_bytes", null );
		}
		return struct;
	}
	
}
