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
 * The EnclosingMethod attribute is an optional fixed-length attribute in the
 * attributes table of a ClassFile (?4.1) structure. A class must have an
 * EnclosingMethod attribute if and only if it is a local class or an anonymous class.
 * A class may have no more than one EnclosingMethod attribute.
 * <p>
 * The EnclosingMethod attribute has the following format:
 * <pre>
 * 	EnclosingMethod_attribute {
 * 		u2 attribute_name_index;
 * 		u4 attribute_length;
 * 		u2 class_index;
 * 		u2 method_index;
 * 	}
 * </pre>
 */
public class EnclosingMethodAttribute extends AbstractAttributeInfo {

	private short classIndex;
	private short methodIndex;

	public EnclosingMethodAttribute(BinaryReader reader) throws IOException {
		super(reader);

		classIndex = reader.readNextShort();
		methodIndex = reader.readNextShort();
	}

	/**
	 * The value of the class_index item must be a valid index into the
	 * constant_pool table. The constant_pool entry at that index must be a
	 * CONSTANT_Class_info structure representing the innermost class that
	 * encloses the declaration of the current class.
	 * @return a valid index into the constant_pool table
	 */
	public int getClassIndex() {
		return classIndex & 0xffff;
	}

	/**
	 * If the current class is not immediately enclosed by a method or constructor,
	 * then the value of the method_index item must be zero.
	 * <p>
	 * Otherwise, the value of the method_index item must be a valid index into
	 * the constant_pool table. The constant_pool entry at that index must be a
	 * CONSTANT_NameAndType_info structure representing the name and
	 * type of a method in the class referenced by the class_index attribute above.
	 * @return a valid index into the constant_pool table, or zero
	 */
	public int getMethodIndex() {
		return methodIndex & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = getBaseStructure("EnclosingMethod_attribute");
		structure.add(WORD, "class_index", null);
		structure.add(WORD, "method_index", null);
		return structure;
	}

}
