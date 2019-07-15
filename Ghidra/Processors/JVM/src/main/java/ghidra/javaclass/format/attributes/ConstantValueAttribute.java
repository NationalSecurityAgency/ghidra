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
 * The ConstantValue attribute is a fixed-length attribute in the attributes table
 * of a field_info structure.
 * <p> 
 * A ConstantValue attribute represents the value
 * of a constant field. There can be no more than one ConstantValue attribute in the
 * attributes table of a given field_info structure. If the field is static (that is,
 * the ACC_STATIC flag (Table 4.19) in the access_flags item of the field_info
 * structure is set) then the constant field represented by the field_info structure
 * is assigned the value referenced by its ConstantValue attribute as part of the
 * initialization of the class or interface declaring the constant field (?5.5). This occurs
 * prior to the invocation of the class or interface initialization method (?2.9) of that
 * class or interface.
 * <p>
 * If a field_info structure representing a non-static field has a ConstantValue
 * attribute, then that attribute must silently be ignored. Every Java virtual machine
 * implementation must recognize ConstantValue attributes.
 * <p>
 * The ConstantValue attribute has the following format:
 * <pre>
 * 	ConstantValue_attribute {
 * 		u2 attribute_name_index;
 * 		u4 attribute_length;
 * 		u2 constantvalue_index;
 * 	}
 * </pre>
 */
public class ConstantValueAttribute extends AbstractAttributeInfo {

	private short constantValueIndex;

	public ConstantValueAttribute(BinaryReader reader) throws IOException {
		super(reader);
		constantValueIndex = reader.readNextShort();
	}

	/**
	 * The value of the constantvalue_index item must be a valid index into
	 * the constant_pool table. The constant_pool entry at that index gives the
	 * constant value represented by this attribute. The constant_pool entry must be
	 * of a type appropriate to the field, as shown by Table 4.22.
	 * <pre>
	 * Table 4.22. Constant value attribute types
	 * --------------------------------------------------
	 * Field Type 						Entry Type
	 * --------------------------------------------------
	 * long								CONSTANT_Long
	 * float							CONSTANT_Float
	 * double							CONSTANT_Double
	 * int, short, char, byte, boolean	CONSTANT_Integer
	 * String							CONSTANT_String
	 * --------------------------------------------------
	 * </pre>
	 * @return a valid index into the constant_pool table
	 */
	public int getConstantValueIndex() {
		return constantValueIndex & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = getBaseStructure("ConstantValue_attribute");
		structure.add(WORD, "constantvalue_index", null);
		return structure;
	}

}
