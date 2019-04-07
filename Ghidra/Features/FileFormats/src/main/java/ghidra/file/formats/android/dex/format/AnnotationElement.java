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

import java.io.IOException;

public class AnnotationElement implements StructConverter {

	private int nameIndex;
	private int nameIndexLength;// in bytes
	private EncodedValue value;

	public AnnotationElement( BinaryReader reader ) throws IOException {
		nameIndex = Leb128.readUnsignedLeb128( reader.readByteArray( reader.getPointerIndex( ), 5 ) );

		nameIndexLength = Leb128.unsignedLeb128Size( nameIndex );
		reader.setPointerIndex( reader.getPointerIndex( ) + nameIndexLength );

		value = new EncodedValue( reader );
	}

	public int getNameIndex( ) {
		return nameIndex;
	}

	public EncodedValue getValue( ) {
		return value;
	}

	@Override
	public DataType toDataType( ) throws DuplicateNameException, IOException {
		DataType encodeValueDataType = value.toDataType( );

		String name = "annotation_element" + "_" + nameIndexLength + "_" + encodeValueDataType.getName( );

		Structure structure = new StructureDataType( name, 0 );

		structure.add( new ArrayDataType( BYTE, nameIndexLength, BYTE.getLength( ) ), "nameIndex", null );

		structure.add( encodeValueDataType, "value", null );

		structure.setCategoryPath( new CategoryPath( "/dex/annotation_element" ) );
		// try {
		// structure.setName( name + "_" + structure.getLength( ) );
		// }
		// catch ( Exception e ) {
		// // ignore
		// }
		return structure;
	}
}
