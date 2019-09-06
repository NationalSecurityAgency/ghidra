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
 *
 */
public abstract class AbstractConstantPoolReferenceInfo extends AbstractConstantPoolInfoJava {

	private short classIndex;
	private short nameAndTypeIndex;

	protected AbstractConstantPoolReferenceInfo(BinaryReader reader) throws IOException {
		super(reader);
		classIndex = reader.readNextShort();
		nameAndTypeIndex = reader.readNextShort();
	}

	/**
	 * The value of the class_index item must be a valid index into the
	 * constant_pool table. The constant_pool entry at that index must be a
	 * CONSTANT_Class_info structure representing a class or interface type
	 * that has the field or method as a member.
	 * <p>
	 * The class_index item of a CONSTANT_Methodref_info structure must be a
	 * class type, not an interface type.
	 * <p>
	 * The class_index item of a CONSTANT_InterfaceMethodref_info structure
	 * must be an interface type.
	 * <p>
	 * The class_index item of a CONSTANT_Fieldref_info structure may be either
	 * a class type or an interface type.
	 * <p>
	 * @return a valid index into the constant_pool table
	 */
	public int getClassIndex() {
		return classIndex & 0xffff;
	}

	/**
	 * The value of the name_and_type_index item must be a valid index into
	 * the constant_pool table. The constant_pool entry at that index must be a
	 * CONSTANT_NameAndType_info structure. This constant_pool entry
	 * indicates the name and descriptor of the field or method.
	 * <p>
	 * In a CONSTANT_Fieldref_info, the indicated descriptor must be a field
	 * descriptor (?4.3.2). Otherwise, the indicated descriptor must be a method
	 * descriptor (?4.3.3).
	 * <p>
	 * If the name of the method of a CONSTANT_Methodref_info structure begins
	 * with a '<' ('\u003c'), then the name must be the special name <init>,
	 * representing an instance initialization method. The return type of such
	 * a method must be void.
	 * <p>
	 * @return a valid index into the constant_pool table
	 */
	public int getNameAndTypeIndex() {
		return nameAndTypeIndex & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "unnamed";
		Structure structure = new StructureDataType(name, 0);
		structure.add(BYTE, "tag", null);
		structure.add(WORD, "class_index", null);
		structure.add(WORD, "name_and_type_index", null);
		return structure;
	}

}
