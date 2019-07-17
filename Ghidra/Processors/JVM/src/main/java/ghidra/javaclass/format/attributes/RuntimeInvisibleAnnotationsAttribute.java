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
package ghidra.javaclass.format.attributes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * The RuntimeVisibleAnnotations attribute is a variable-length attribute in the
 * attributes table of a ClassFile, field_info or method_info structure. 
 * <p>
 * The RuntimeVisibleAnnotations attribute records runtimevisible
 * Java programming language annotations on the corresponding class, field,
 * or method.
 * <p>
 * Each ClassFile, field_info, and method_info structure may contain at most
 * one RuntimeVisibleAnnotations attribute, which records all the runtime-visible
 * Java programming language annotations on the corresponding program element.
 * <p>
 * The Java virtual machine must make these annotations available so they can be
 * returned by the appropriate reflective APIs.
 * <p>
 * The RuntimeVisibleAnnotations attribute has the following format:
 * <pre>
 * 	RuntimeVisibleAnnotations_attribute {
 * 		u2 attribute_name_index;
 * 		u4 attribute_length;
 * 		u2 num_annotations;
 * 		annotation annotations[num_annotations];
 * 	}
 * </pre>
 */
public class RuntimeInvisibleAnnotationsAttribute extends AbstractAttributeInfo {

	private short numberOfAnnotations;
	private AnnotationJava[] annotations;

	public RuntimeInvisibleAnnotationsAttribute(BinaryReader reader) throws IOException {
		super(reader);

		numberOfAnnotations = reader.readNextShort();

		annotations = new AnnotationJava[getNumberOfAnnotations()];

		for (int i = 0; i < getNumberOfAnnotations(); ++i) {
			annotations[i] = new AnnotationJava(reader);
		}
	}

	/**
	 * The value of the num_annotations item gives the number of runtime-visible
	 * annotations represented by the structure.
	 * <p>
	 * Note that a maximum of 65535 runtime-visible Java programming language annotations
	 * may be directly attached to a program element.
	 * @return the number of runtime-visible annotations
	 */
	public int getNumberOfAnnotations() {
		return numberOfAnnotations & 0xffff;
	}

	/**
	 * Returns the annotations table of a single runtime-visible
	 * annotation on a program element.
	 * @return the annotations table
	 */
	public AnnotationJava[] getAnnotations() {
		return annotations;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "RuntimeInvisibleAnnotations_attribute" + "|" + numberOfAnnotations + "|";
		StructureDataType structure = getBaseStructure(name);
		structure.add(WORD, "num_annotations", null);
		for (int i = 0; i < annotations.length; ++i) {
			structure.add(annotations[i].toDataType(), "annotation_" + i, null);
		}
		return structure;
	}

}
