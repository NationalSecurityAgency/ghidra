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
package ghidra.javaclass.format.constantpool;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * The CONSTANT_NameAndType_info structure is used to represent a field or method,
 * without indicating which class or interface type it belongs to:
 * <pre>
 * 		CONSTANT_NameAndType_info {
 * 			u1 tag;
 * 			u2 name_index;
 * 			u2 descriptor_index;
 *		}
 * </pre>
 */
public class ConstantPoolNameAndTypeInfo extends AbstractConstantPoolInfoJava {

	private short nameIndex;
	private short descriptorIndex;

	public ConstantPoolNameAndTypeInfo(BinaryReader reader) throws IOException {
		super(reader);
		nameIndex = reader.readNextShort();
		descriptorIndex = reader.readNextShort();
	}

	/**
	 * The value of the name_index item must be a valid index into the
	 * constant_pool table. The constant_pool entry at that index must be a
	 * CONSTANT_Utf8_info structure representing either the special method
	 * name <init> or a valid unqualified name denoting a field or
	 * method.
	 * @return a valid index into the constant_pool table to the name
	 */
	public int getNameIndex() {
		return nameIndex & 0xffff;
	}

	/**
	 * The value of the descriptor_index item must be a valid index into the
	 * constant_pool table. The constant_pool entry at that index must be a
	 * CONSTANT_Utf8_info structure representing a valid field descriptor
	 * or method descriptor.
	 * @return a valid index into the constant_pool table to the descriptor
	 */
	public int getDescriptorIndex() {
		return descriptorIndex & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "CONSTANT_NameAndType_info";
		Structure structure = new StructureDataType(name, 0);
		structure.add(BYTE, "tag", null);
		structure.add(WORD, "name_index", null);
		structure.add(WORD, "descriptor_index", null);
		return structure;
	}

}
