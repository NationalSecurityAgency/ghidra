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
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

/**
 * 
 * field_annotation format
 * 
 * Name Format Description
 * 
 * field_idx uint index into the field_ids list for the identity of the field being annotated
 * 
 * annotations_off uint offset from the start of the file to the list of annotations for the field. The offset should be to a location in the data section. The format of the data is specified by
 * "annotation_set_item" below.
 * 
 */
public class FieldAnnotation implements StructConverter {

	private int fieldIndex;
	private int annotationsOffset;

	private AnnotationSetItem _annotationSetItem;

	public FieldAnnotation( BinaryReader reader ) throws IOException {
		fieldIndex = reader.readNextInt( );
		annotationsOffset = reader.readNextInt( );

		if ( annotationsOffset > 0 ) {
			long oldIndex = reader.getPointerIndex( );
			try {
				reader.setPointerIndex( annotationsOffset );
				_annotationSetItem = new AnnotationSetItem( reader );
			}
			finally {
				reader.setPointerIndex( oldIndex );
			}
		}
	}

	public int getFieldIndex( ) {
		return fieldIndex;
	}

	public int getAnnotationsOffset( ) {
		return annotationsOffset;
	}

	public AnnotationSetItem getAnnotationSetItem( ) {
		return _annotationSetItem;
	}

	@Override
	public DataType toDataType( ) throws DuplicateNameException, IOException {
		DataType dataType = StructConverterUtil.toDataType( FieldAnnotation.class );
		dataType.setCategoryPath( new CategoryPath( "/dex" ) );
		return dataType;
	}

}
