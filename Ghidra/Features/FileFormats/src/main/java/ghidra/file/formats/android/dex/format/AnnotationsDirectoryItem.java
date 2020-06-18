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
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.android.dex.util.DexUtil;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/art/+/master/libdexfile/dex/dex_file_structs.h#209
 */
public class AnnotationsDirectoryItem implements StructConverter {

	private int classAnnotationsOffset;
	private int fieldsSize;
	private int annotatedMethodsSize;
	private int annotatedParametersSize;
	private List<FieldAnnotationsItem> fieldAnnotations = new ArrayList<FieldAnnotationsItem>();
	private List<MethodAnnotationsItem> methodAnnotations = new ArrayList<MethodAnnotationsItem>();
	private List<ParameterAnnotationsItem> parameterAnnotations =
		new ArrayList<ParameterAnnotationsItem>();
	private AnnotationSetItem _classAnnotations;

	public AnnotationsDirectoryItem(BinaryReader reader, DexHeader dexHeader) throws IOException {

		classAnnotationsOffset = reader.readNextInt();
		fieldsSize = reader.readNextInt();
		annotatedMethodsSize = reader.readNextInt();
		annotatedParametersSize = reader.readNextInt();

		for (int i = 0; i < fieldsSize; ++i) {
			fieldAnnotations.add(new FieldAnnotationsItem(reader, dexHeader));
		}
		for (int i = 0; i < annotatedMethodsSize; ++i) {
			methodAnnotations.add(new MethodAnnotationsItem(reader, dexHeader));
		}

		if (classAnnotationsOffset > 0) {
			long oldIndex = reader.getPointerIndex();
			try {
				reader.setPointerIndex(DexUtil.adjustOffset(classAnnotationsOffset, dexHeader));
				_classAnnotations = new AnnotationSetItem(reader, dexHeader);
			}
			finally {
				reader.setPointerIndex(oldIndex);
			}
		}
	}

	public int getClassAnnotationsOffset() {
		return classAnnotationsOffset;
	}

	public int getFieldsSize() {
		return fieldsSize;
	}

	public int getAnnotatedMethodsSize() {
		return annotatedMethodsSize;
	}

	public int getAnnotatedParametersSize() {
		return annotatedParametersSize;
	}

	public List<FieldAnnotationsItem> getFieldAnnotations() {
		return Collections.unmodifiableList(fieldAnnotations);
	}

	public List<MethodAnnotationsItem> getMethodAnnotations() {
		return Collections.unmodifiableList(methodAnnotations);
	}

	public List<ParameterAnnotationsItem> getParameterAnnotations() {
		return Collections.unmodifiableList(parameterAnnotations);
	}

	public AnnotationSetItem getClassAnnotations() {
		return _classAnnotations;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("annotations_directory_item_" + fieldsSize +
			"_" + annotatedMethodsSize + "_" + annotatedParametersSize, 0);
		structure.add(DWORD, "class_annotations_off", null);
		structure.add(DWORD, "fields_size", null);
		structure.add(DWORD, "annotated_methods_size", null);
		structure.add(DWORD, "annotated_parameters_size", null);
		int index = 0;
		for (FieldAnnotationsItem field : fieldAnnotations) {
			structure.add(field.toDataType(), "field_" + index, null);
			++index;
		}
		index = 0;
		for (MethodAnnotationsItem method : methodAnnotations) {
			structure.add(method.toDataType(), "method_" + index, null);
			++index;
		}
		index = 0;
		for (ParameterAnnotationsItem parameter : parameterAnnotations) {
			structure.add(parameter.toDataType(), "parameter_" + index, null);
			++index;
		}
		structure.setCategoryPath(new CategoryPath("/dex/annotations_directory_item"));
		return structure;
	}

}
