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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class EncodedArray implements StructConverter {

	private int size;
	private int sizeLength;// in bytes
	// private List< EncodedValue > values = new ArrayList< EncodedValue >( );
	private byte [] values;

	public EncodedArray( BinaryReader reader ) throws IOException {
		LEB128 leb128 = LEB128.readUnsignedValue(reader);
		size = leb128.asUInt32();
		sizeLength = leb128.getLength();

		BinaryReader evReader = reader.clone();
		List< EncodedValue > valuesList = new ArrayList< >( );
		for ( int i = 0 ; i < size ; ++i ) {
			valuesList.add(new EncodedValue(evReader));
		}
		int nBytes = (int) (evReader.getPointerIndex() - reader.getPointerIndex());
		values = reader.readNextByteArray(nBytes);		// Re-read the encoded values as a byte array
	}

	public int getSize( ) {
		return size;
	}

	public byte [] getValues( ) {
		return values;
	}

	@Override
	public DataType toDataType( ) throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType( "encoded_array_" + values.length, 0 );
		structure.add( new ArrayDataType( BYTE, sizeLength, BYTE.getLength( ) ), "size", null );
		if ( values.length > 0 ) {
			structure.add( new ArrayDataType( BYTE, values.length, BYTE.getLength( ) ), "values", null );
		}
		// int index = 0;
		// for ( EncodedValue value : values ) {
		// structure.add( value.toDataType( ), "value" + index, null );
		// ++index;
		// }
		structure.setCategoryPath( new CategoryPath( "/dex/encoded_array" ) );
		return structure;
	}

}
