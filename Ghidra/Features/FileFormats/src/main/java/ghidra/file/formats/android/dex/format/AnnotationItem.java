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

/**
 * 
 * https://android.googlesource.com/platform/art/+/master/libdexfile/dex/dex_file_structs.h
 *
 */
public class AnnotationItem implements StructConverter {

	private byte visibility;
	private EncodedAnnotation annotation;

	public AnnotationItem(BinaryReader reader) throws IOException {
		visibility = reader.readNextByte();
		annotation = new EncodedAnnotation(reader);
	}

	public byte getVisibility() {
		return visibility;
	}

	public EncodedAnnotation getAnnotation() {
		return annotation;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		DataType annotationDataType = annotation.toDataType();

		StringBuilder builder = new StringBuilder();
		builder.append("annotation_item" + "_");
		builder.append(visibility + "_");
		builder.append(annotationDataType.getName());

		Structure structure = new StructureDataType(builder.toString(), 0);
		structure.add(BYTE, "visibility", null);
		structure.add(annotationDataType, "annotation", null);

		builder.append(structure.getLength() + "_");

		structure.setCategoryPath(new CategoryPath("/dex/annotation_item"));
		try {
			structure.setName(builder.toString());
		}
		catch (Exception e) {
			// ignore
		}
		return structure;
	}

}
