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
import ghidra.app.util.bin.StructConverter;
import ghidra.javaclass.format.DescriptorDecoder;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * The element_value structure is a discriminated union representing the
 * value of an element-value pair. It is used to represent element values
 * in all attributes that describe annotations:
 * 		RuntimeVisibleAnnotations,
 * 		RuntimeInvisibleAnnotations, 
 * 		RuntimeVisibleParameterAnnotations, and
 * 		RuntimeInvisibleParameterAnnotations.
 * <p>
 * The element_value structure has the following format:
 * <pre>
 * 	element_value {
 * 		u1 tag;
 * 		union {
 * 			u2 const_value_index;
 * 			{
 * 				u2 type_name_index;
 * 				u2 const_name_index;
 * 			} enum_const_value;
 * 			u2 class_info_index;
 * 			annotation annotation_value;
 * 			{
 * 				u2 num_values;
 * 				element_value values[num_values];
 * 			} array_value;
 * 		} value;
 * 	}
 * </pre>
 */
public class AnnotationElementValue implements StructConverter {

	private byte tag;

	private short constantValueIndex;

	private short typeNameIndex;
	private short constantNameIndex;

	private short classInfoIndex;

	private AnnotationJava annotation;

	private short numberOfValues;
	private AnnotationElementValue[] values;

	public AnnotationElementValue(BinaryReader reader) throws IOException {
		tag = reader.readNextByte();

		if (tag == DescriptorDecoder.BASE_TYPE_BYTE || tag == DescriptorDecoder.BASE_TYPE_CHAR ||
			tag == DescriptorDecoder.BASE_TYPE_INT || tag == DescriptorDecoder.BASE_TYPE_SHORT ||
			tag == DescriptorDecoder.BASE_TYPE_LONG || tag == DescriptorDecoder.BASE_TYPE_FLOAT ||
			tag == DescriptorDecoder.BASE_TYPE_DOUBLE ||
			tag == DescriptorDecoder.BASE_TYPE_BOOLEAN ||
			tag == DescriptorDecoder.BASE_TYPE_STRING) {

			constantValueIndex = reader.readNextShort();
		}
		else if (tag == DescriptorDecoder.BASE_TYPE_ENUM) {
			typeNameIndex = reader.readNextShort();
			constantNameIndex = reader.readNextShort();
		}
		else if (tag == DescriptorDecoder.BASE_TYPE_CLASS) {
			classInfoIndex = reader.readNextShort();
		}
		else if (tag == DescriptorDecoder.BASE_TYPE_ANNOTATION) {
			annotation = new AnnotationJava(reader);
		}
		else if (tag == DescriptorDecoder.BASE_TYPE_ARRAY) {
			numberOfValues = reader.readNextShort();
			values = new AnnotationElementValue[numberOfValues & 0xffff];
			for (int i = 0; i < (numberOfValues & 0xffff); ++i) {
				values[i] = new AnnotationElementValue(reader);
			}
		}
	}

	/**
	 * The tag item indicates the type of this annotation element-value pair.
	 * <p>
	 * The letters 'B', 'C', 'D', 'F', 'I', 'J', 'S', and 'Z' indicate a primitive type.
	 * <p> 
	 * These letters are interpreted as BaseType characters ( Table 4.2 ).
	 * <p> 
	 * The other legal values for tag are listed with their interpretations in Table 4.24.
	 * @see DataTypeDecoder
	 * @return the type of this annotation element-value pair
	 */
	public byte getTag() {
		return tag;
	}

	/**
	 * The const_value_index item is used if the tag item is one of 
	 * 		'B', 
	 * 		'C', 
	 * 		'D',
	 * 		'F', 
	 * 		'I', 
	 * 		'J', 
	 * 		'S', 
	 * 		'Z', 
	 * 		's'. 
	 * The value of the const_value_index item must be
	 * a valid index into the constant_pool table. 
	 * <p>
	 * The constant_pool entry at that index must be of the correct entry type 
	 * for the field type designated by the tag item, as specified in Table 4.24.
	 * @return a valid index into the constant_pool table
	 */
	public int getConstantValueIndex() {
		return constantValueIndex & 0xffff;
	}

	/**
	 * The value of the type_name_index item must be a valid index into
	 * the constant_pool table. The constant_pool entry at that index
	 * must be a CONSTANT_Utf8_info (?4.4.7) structure representing a valid
	 * field descriptor (?4.3.2) that denotes the internal form of the binary
	 * name (?4.2.1) of the type of the enum constant represented by this
	 * element_value structure.
	 * @return a valid index into the constant_pool table
	 */
	public int getTypeNameIndex() {
		if (tag != DescriptorDecoder.BASE_TYPE_ENUM) {
			throw new IllegalArgumentException();
		}
		return typeNameIndex & 0xffff;
	}

	/**
	 * The value of the const_name_index item must be a valid index into
	 * the constant_pool table. The constant_pool entry at that index
	 * must be a CONSTANT_Utf8_info (?4.4.7) structure representing the
	 * simple name of the enum constant represented by this element_value
	 * structure.
	 * @return a valid index into the constant_pool table
	 */
	public int getConstantNameIndex() {
		if (tag != DescriptorDecoder.BASE_TYPE_ENUM) {
			throw new IllegalArgumentException();
		}
		return constantNameIndex & 0xffff;
	}

	/**
	 * The class_info_index item is used if the tag item is 'c'.
	 * The class_info_index item must be a valid index into the
	 * constant_pool table. The constant_pool entry at that index must be a
	 * CONSTANT_Utf8_info (?4.4.7) structure representing the return descriptor
	 * (?4.3.3) of the type that is reified by the class represented by this
	 * element_value structure.
	 * For example, 'V' for Void.class, 'Ljava/lang/Object;' for Object, etc.
	 * @return a valid index into the constant_pool table
	 */
	public int getClassInfoIndex() {
		return classInfoIndex & 0xffff;
	}

	/**
	 * The annotation_value item is used if the tag item is '@'. 
	 * The element_value structure represents a "nested" annotation.
	 * @return a "nested" annotation
	 */
	public AnnotationJava getAnnotation() {
		return annotation;
	}

	/**
	 * The value of the num_values item gives the number of elements in the
	 * array-typed value represented by this element_value structure.
	 * <p>
	 * Note that a maximum of 65535 elements are permitted in an array-typed element value.
	 * <p>
	 * Each value of the values table gives the value of an element of the
	 * array-typed value represented by this element_value structure.
	 * @return nested element value table
	 */
	public AnnotationElementValue[] getValues() {
		return values;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "element_value" + "|" + tag + "|";
		StructureDataType structure = new StructureDataType(name, 0);

		if (tag == DescriptorDecoder.BASE_TYPE_BYTE || tag == DescriptorDecoder.BASE_TYPE_CHAR ||
			tag == DescriptorDecoder.BASE_TYPE_INT || tag == DescriptorDecoder.BASE_TYPE_SHORT ||
			tag == DescriptorDecoder.BASE_TYPE_LONG || tag == DescriptorDecoder.BASE_TYPE_FLOAT ||
			tag == DescriptorDecoder.BASE_TYPE_DOUBLE ||
			tag == DescriptorDecoder.BASE_TYPE_BOOLEAN ||
			tag == DescriptorDecoder.BASE_TYPE_STRING) {
		}
		else if (tag == DescriptorDecoder.BASE_TYPE_ENUM) {
		}
		else if (tag == DescriptorDecoder.BASE_TYPE_CLASS) {
		}
		else if (tag == DescriptorDecoder.BASE_TYPE_ANNOTATION) {
		}
		else if (tag == DescriptorDecoder.BASE_TYPE_ARRAY) {
		}

		return structure;
	}

}
