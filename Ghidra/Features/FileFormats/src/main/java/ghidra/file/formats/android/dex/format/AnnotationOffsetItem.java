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

public class AnnotationOffsetItem implements StructConverter {

	private int annotationsOffset;

	private AnnotationItem _item;

	public AnnotationOffsetItem( BinaryReader reader ) throws IOException {
		annotationsOffset = reader.readNextInt( );

		if ( annotationsOffset > 0 ) {
			long oldIndex = reader.getPointerIndex( );
			try {
				reader.setPointerIndex( annotationsOffset );
				_item = new AnnotationItem( reader );
			}
			finally {
				reader.setPointerIndex( oldIndex );
			}
		}
	}

	public int getAnnotationsOffset( ) {
		return annotationsOffset;
	}

	public AnnotationItem getItem( ) {
		return _item;
	}

	@Override
	public DataType toDataType( ) throws DuplicateNameException, IOException {
		DataType dataType = StructConverterUtil.toDataType( AnnotationOffsetItem.class );
		dataType.setCategoryPath( new CategoryPath( "/dex" ) );
		return dataType;
	}

}
