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
package ghidra.javaclass.format;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.javaclass.format.attributes.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * Each field is described by a field_info structure. No two fields in one class file
 * may have the same name and descriptor
 * <p>
 * The structure has the following format:
 * <pre>
 * 		field_info {
 * 			u2 access_flags;
 * 			u2 name_index;
 * 			u2 descriptor_index;
 * 			u2 attributes_count;
 * 			attribute_info attributes[attributes_count];
 * 		}
 * </pre>
 */
public class FieldInfoJava implements StructConverter {

	private long _offset;

	private short accessFlags;
	private short nameIndex;
	private short descriptorIndex;
	private short attributesCount;
	private AbstractAttributeInfo[] attributes;

	public FieldInfoJava(BinaryReader reader, ClassFileJava classFile) throws IOException {
		_offset = reader.getPointerIndex();

		accessFlags = reader.readNextShort();
		nameIndex = reader.readNextShort();
		descriptorIndex = reader.readNextShort();
		attributesCount = reader.readNextShort();
		attributes = new AbstractAttributeInfo[getAttributesCount()];
		for (int i = 0; i < getAttributesCount(); i++) {
			attributes[i] = AttributeFactory.get(reader, classFile.getConstantPool());
		}
	}

	public long getOffset() {
		return _offset;
	}

	/**
	 * The value of the access_flags item is a mask of flags used to denote access
	 * permission to and properties of this field. The interpretation of each flag, when
	 * set, is as shown in Table 4.19.
	 * @return a mask of flags used to denote access permission to and properties of this field
	 */
	public short getAccessFlags() {
		return accessFlags;
	}

	/**
	 * The value of the name_index item must be a valid index into the
	 * constant_pool table. The constant_pool entry at that index must be
	 * a CONSTANT_Utf8_info structure which must represent a valid
	 * unqualified name denoting a field.
	 * @return a valid index into the constant_pool table
	 */
	public int getNameIndex() {
		return nameIndex & 0xffff;
	}

	/**
	 * The value of the descriptor_index item must be a valid index into the
	 * constant_pool table. The constant_pool entry at that index must be a
	 * CONSTANT_Utf8_info structure that must represent a valid field
	 * descriptor.
	 * @return a valid index into the constant_pool table
	 */
	public int getDescriptorIndex() {
		return descriptorIndex & 0xffff;
	}

	/**
	 * The value of the attributes_count item indicates the number of additional
	 * attributes of this field.
	 * @return the number of additional attributes
	 */
	public int getAttributesCount() {
		return attributesCount & 0xffff;
	}

	/**
	 * Each value of the attributes table must be an attribute structure. A
	 * field can have any number of attributes associated with it.
	 * <p>
	 * The attributes defined by this specification as appearing
	 * in the attributes table of a field_info structure are
	 * 		ConstantValue, 
	 * 		Synthetic, 
	 * 		Signature,
	 * 		Deprecated, 
	 * 		RuntimeVisibleAnnotations and
	 * 		RuntimeInvisibleAnnotations.
	 * <p>
	 * A Java virtual machine implementation must recognize and correctly read
	 * ConstantValue attributes found in the attributes table of a
	 * field_info structure. If a Java virtual machine implementation recognizes
	 * class files whose version number is 49.0 or above, it must recognize and
	 * correctly read Signature, RuntimeVisibleAnnotations
	 * and RuntimeInvisibleAnnotations attributes found in the
	 * attributes table of a field_info structure of a class file whose version
	 * number is 49.0 or above.
	 * <p>
	 * A Java virtual machine implementation is required to silently ignore any or all
	 * attributes that it does not recognize in the attributes table of a field_info
	 * structure. Attributes not defined in this specification are not allowed to affect
	 * the semantics of the class file, but only to provide additional descriptive
	 * information.
	 * @return
	 */
	public AbstractAttributeInfo[] getAttributes() {
		return attributes;
	}

	public ConstantValueAttribute getConstantValueAttribute() {
		for (AbstractAttributeInfo attributeInfo : attributes) {
			if (attributeInfo instanceof ConstantValueAttribute) {
				return (ConstantValueAttribute) attributeInfo;
			}
		}
		return null;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "field_info" + "|" + attributesCount + "|";

		Structure structure = new StructureDataType(name, 0);

		structure.add(WORD, "access_flags", null);
		structure.add(WORD, "name_index", null);
		structure.add(WORD, "descriptor_index", null);
		structure.add(WORD, "attributes_count", null);

		for (int i = 0; i < attributes.length; ++i) {
			structure.add(attributes[i].toDataType(), "attributes_" + i, null);
		}

		return structure;
	}

}
