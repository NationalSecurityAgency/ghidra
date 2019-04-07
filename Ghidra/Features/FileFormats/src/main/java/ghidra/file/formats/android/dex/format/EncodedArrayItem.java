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
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class EncodedArrayItem implements StructConverter {

	private EncodedArray array;

	public EncodedArrayItem( BinaryReader reader ) throws IOException {
		array = new EncodedArray( reader );
	}

	public EncodedArray getArray( ) {
		return array;
	}

	@Override
	public DataType toDataType( ) throws DuplicateNameException, IOException {
		DataType dataType = array.toDataType( );
		Structure structure = new StructureDataType( "encoded_array_item_" + dataType.getLength( ), 0 );
		structure.add( dataType, "value", null );
		structure.setCategoryPath( new CategoryPath( "/dex/encoded_array_item" ) );
		return structure;
	}

}
