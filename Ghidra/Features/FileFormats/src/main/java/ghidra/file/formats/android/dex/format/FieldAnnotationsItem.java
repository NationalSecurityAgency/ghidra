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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.file.formats.android.dex.util.DexUtil;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

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
 * https://android.googlesource.com/platform/art/+/master/libdexfile/dex/dex_file_structs.h
 */
public class FieldAnnotationsItem implements StructConverter {

	private int fieldIndex;
	private int annotationsOffset;

	private AnnotationSetItem _annotationSetItem;

	public FieldAnnotationsItem(BinaryReader reader, DexHeader dexHeader) throws IOException {
		fieldIndex = reader.readNextInt();
		annotationsOffset = reader.readNextInt();

		if (annotationsOffset > 0) {
			BinaryReader clonedReader = reader.clone(DexUtil.adjustOffset(annotationsOffset, dexHeader));
			_annotationSetItem = new AnnotationSetItem(clonedReader, dexHeader);
		}
	}

	public int getFieldIndex() {
		return fieldIndex;
	}

	public int getAnnotationsOffset() {
		return annotationsOffset;
	}

	public AnnotationSetItem getAnnotationSetItem() {
		return _annotationSetItem;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		DataType dataType = StructConverterUtil.toDataType(FieldAnnotationsItem.class);
		dataType.setCategoryPath(new CategoryPath("/dex"));
		return dataType;
	}

}
