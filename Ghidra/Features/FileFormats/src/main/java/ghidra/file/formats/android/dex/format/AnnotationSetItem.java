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
import java.util.*;

/**
 * annotation_set_item
 * 
 * referenced from annotations_directory_item, field_annotations_item, method_annotations_item, and annotation_set_ref_item
 * 
 * appears in the data section
 * 
 * alignment: 4 bytes
 */
public class AnnotationSetItem implements StructConverter {

	private int size;
	private List<AnnotationOffsetItem> items = new ArrayList<AnnotationOffsetItem>();

	public AnnotationSetItem( BinaryReader reader ) throws IOException {
		size = reader.readNextInt( );

		for ( int i = 0 ; i < size ; ++i ) {
			items.add( new AnnotationOffsetItem( reader ) );
		}
	}

	public int getSize( ) {
		return size;
	}

	public List< AnnotationOffsetItem > getItems( ) {
		return Collections.unmodifiableList( items );
	}

	@Override
	public DataType toDataType( ) throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType( "annotation_set_item_" + size, 0 );
		structure.add( DWORD, "size", null );
		int index = 0;
		for ( AnnotationOffsetItem item : items ) {
			structure.add( item.toDataType( ), "item" + index, null );
			++index;
		}
		structure.setCategoryPath( new CategoryPath( "/dex/annotation_set_item" ) );
		return structure;
	}

}
