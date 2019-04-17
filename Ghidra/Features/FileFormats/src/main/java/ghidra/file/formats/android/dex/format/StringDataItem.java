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
package ghidra.file.formats.android.dex.format;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.android.dex.util.Leb128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class StringDataItem implements StructConverter {

	private int stringLength;
	private int lebLength;
	private int actualLength;
	private String string;

	public StringDataItem( StringIDItem stringItem, BinaryReader reader ) throws IOException {
		long oldIndex = reader.getPointerIndex( );
		try {
			reader.setPointerIndex( stringItem.getStringDataOffset( ) );
			stringLength = Leb128.readUnsignedLeb128( reader.readByteArray( stringItem.getStringDataOffset( ), 5 ) );

			lebLength = Leb128.unsignedLeb128Size( stringLength );

			reader.readNextByteArray( lebLength );// consume leb...

			actualLength = computeActualLength( reader );

			byte [] stringBytes = reader.readNextByteArray( actualLength );

			ByteArrayInputStream in = new ByteArrayInputStream( stringBytes );

			char [] out = new char[ stringLength ];

			string = ModifiedUTF8.decode( in, out );
		}
		finally {
			reader.setPointerIndex( oldIndex );
		}
	}

	public String getString( ) {
		return string;
	}

	@Override
	public DataType toDataType( ) throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType( "string_data_item_" + actualLength, 0 );
		structure.add( new ArrayDataType( BYTE, lebLength, BYTE.getLength( ) ), "utf16_size", null );
		structure.add( UTF8, actualLength, "data", null );
		structure.setCategoryPath( new CategoryPath( "/dex/string_data_item" ) );
		return structure;
	}

	private int computeActualLength( BinaryReader reader ) throws IOException {
		int count = 0;
		while ( count < 0x200000 ) {// don't run forever!
			if ( reader.readByte( reader.getPointerIndex( ) + count ) == 0x0 ) {
				break;
			}
			++count;
		}
		return count + 1;
	}

}
