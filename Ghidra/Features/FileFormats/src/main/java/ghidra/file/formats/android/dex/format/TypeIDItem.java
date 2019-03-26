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

import ghidra.app.util.bin.*;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

public class TypeIDItem implements StructConverter {

	@Override
	public int hashCode() {
		return descriptorIndex;
	}

	private int descriptorIndex;

	public TypeIDItem( BinaryReader reader ) throws IOException {
		descriptorIndex = reader.readNextInt( );
	}

	public int getDescriptorIndex( ) {
		return descriptorIndex;
	}

	@Override
	public DataType toDataType( ) throws DuplicateNameException, IOException {
		DataType dataType = StructConverterUtil.toDataType( TypeIDItem.class );
		dataType.setCategoryPath( new CategoryPath( "/dex" ) );
		return dataType;
	}

}
