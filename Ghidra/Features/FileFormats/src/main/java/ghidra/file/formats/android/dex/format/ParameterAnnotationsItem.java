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

public class ParameterAnnotationsItem implements StructConverter {

	private int methodIndex;
	private int annotationsOffset;

	private AnnotationSetReferenceList _annotationSetReferenceList;

	public ParameterAnnotationsItem(BinaryReader reader) throws IOException {
		methodIndex = reader.readNextInt();
		annotationsOffset = reader.readNextInt();

		if (annotationsOffset > 0) {
			long oldIndex = reader.getPointerIndex();
			try {
				reader.setPointerIndex(annotationsOffset);
				_annotationSetReferenceList = new AnnotationSetReferenceList(reader);
			}
			finally {
				reader.setPointerIndex(oldIndex);
			}
		}
	}

	public int getMethodIndex() {
		return methodIndex;
	}

	public int getAnnotationsOffset() {
		return annotationsOffset;
	}

	public AnnotationSetReferenceList getAnnotationSetReferenceList() {
		return _annotationSetReferenceList;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		DataType dataType = StructConverterUtil.toDataType(ParameterAnnotationsItem.class);
		dataType.setCategoryPath(new CategoryPath("/dex"));
		return dataType;
	}

}
