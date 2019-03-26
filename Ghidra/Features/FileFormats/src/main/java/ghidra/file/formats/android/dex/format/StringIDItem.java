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

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class StringIDItem implements StructConverter {

	private int stringDataOffset;
	private StringDataItem _stringDataItem;

	public StringIDItem( BinaryReader reader ) throws IOException {
		stringDataOffset = reader.readNextInt( );

		_stringDataItem = new StringDataItem( this, reader );
	}

	public int getStringDataOffset( ) {
		return stringDataOffset;
	}

	public StringDataItem getStringDataItem( ) {
		return _stringDataItem;
	}

	@Override
	public DataType toDataType( ) throws DuplicateNameException, IOException {
		DataType dataType = StructConverterUtil.toDataType( StringIDItem.class );
		dataType.setCategoryPath( new CategoryPath( "/dex" ) );
		return dataType;
	}

}
