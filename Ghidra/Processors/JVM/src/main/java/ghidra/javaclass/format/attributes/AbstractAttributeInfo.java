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
import ghidra.program.model.data.StructureDataType;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * Attributes are used in the ClassFile, field_info, method_info and 
 * Code_attribute structures of the class file format.
 * <p>
 * All attributes have the following general format:
 * <pre>
 * 		attribute_info {
 * 			u2 attribute_name_index;
 * 			u4 attribute_length;
 * 			u1 info[attribute_length];
 * 		}
 * <pre>
 * <p>
 * For all attributes, the attribute_name_index must be a valid unsigned 
 * 16-bit index into the constant pool of the class. The constant_pool entry
 * at attribute_name_index must be a CONSTANT_Utf8_info structure
 * representing the name of the attribute. 
 * <p>
 * The value of the attribute_length item
 * indicates the length of the subsequent information in bytes. The length does
 * not include the initial six bytes that contain the attribute_name_index and
 * attribute_length items.
 * <p>
 * Certain attributes are predefined as part of the class file specification. They are
 * listed in Table 4.21, accompanied by the version of the Java Platform, Standard
 * Edition ("Java SE") and the version of the class file format in which each first
 * appeared. Within the context of their use in this specification, that is, in the
 * attributes tables of the class file structures in which they appear, the names of
 * these predefined attributes are reserved. Of the predefined attributes:
 * <p>
 * The ConstantValue, Code and Exceptions attributes must be recognized and
 * correctly read by a class file reader for correct interpretation of the class file
 * by a Java virtual machine implementation.
 * <p>
 * The InnerClasses, EnclosingMethod and Synthetic attributes must be
 * recognized and correctly read by a class file reader in order to properly
 * implement the Java platform class libraries.
 * <p>
 * The RuntimeVisibleAnnotations, RuntimeInvisibleAnnotations, RuntimeVisibleParameterAnnotations,
 * RuntimeInvisibleParameterAnnotations and AnnotationDefault attributes
 * must be recognized and correctly read by a class file reader in order to properly
 * implement the Java platform class libraries, if the class file's version
 * number is 49.0 or above and the Java virtual machine implementation recognizes
 * class files whose version number is 49.0 or above.
 * <p>
 * The Signature attribute must be recognized and correctly read by a class file
 * reader if the class file's version number is 49.0 or above and the Java virtual
 * machine implementation recognizes class files whose version number is 49.0
 * or above.
 * <p>
 * The StackMapTable attribute must be recognized and correctly read by a class
 * file reader if the class file's version number is 50.0 or above and the Java virtual
 * machine implementation recognizes class files whose version number is 50.0
 * or above.
 * <p>
 * The BootstrapMethods attribute must be recognized and correctly read by a
 * class file reader if the class file's version number is 51.0 or above and the Java
 * virtual machine implementation recognizes class files whose version number
 * is 51.0 or above.
 * <p>
 * Use of the remaining predefined attributes is optional; a class file reader may use
 * the information they contain, or otherwise must silently ignore those attributes.
 */
public abstract class AbstractAttributeInfo implements StructConverter {

	private long _offset;

	private short attributeNameIndex;
	private int attributeLength;

	protected AbstractAttributeInfo(BinaryReader reader) throws IOException {
		_offset = reader.getPointerIndex();

		attributeNameIndex = reader.readNextShort();
		attributeLength = reader.readNextInt();
	}

	public long getOffset() {
		return _offset;
	}

	/**
	 * The value of the attribute_name_index item must be a valid index
	 * into the constant_pool table. The constant_pool entry at that index
	 * must be a CONSTANT_Utf8_info structure representing the name of this attribute.
	 * @see AttributesConstants
	 * @return the attribute_name_index
	 */
	public int getAttributeNameIndex() {
		return attributeNameIndex & 0xffff;
	}

	/**
	 * The value of the attribute_length item indicates the length of the attribute,
	 * excluding the initial six bytes. 
	 * The value of the attribute_length item is thus dependent on the specific
	 * attribute.
	 * @return the length of the attribute, excluding the initial six bytes
	 */
	public int getAttributeLength() {
		return attributeLength;
	}

	protected StructureDataType getBaseStructure(String name) {
		StructureDataType structure = new StructureDataType(name + "|" + attributeLength + "|", 0);
		structure.add(WORD, "attribute_name_index", null);
		structure.add(DWORD, "attribute_length", null);
		return structure;
	}
}
