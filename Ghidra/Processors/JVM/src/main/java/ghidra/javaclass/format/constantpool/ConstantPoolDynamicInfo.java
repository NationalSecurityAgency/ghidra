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
 * Note: text extracted from jvms12.pdf
 * <p>
 * 
 *   The CONSTANT_Dynamic_info structure is defined as follows:
 *   <pre>
 *   CONSTANT_Dynamic_info {
 *     u1 tag;
 *     u2 bootstrap_method_attr_index;
 *     u2 name_and_type_index;
 *   }
 *   </pre>
*/
public class ConstantPoolDynamicInfo extends AbstractConstantPoolInfoJava {

	private short bootstrap_method_attr_index;
	private short name_and_type_index;

	protected ConstantPoolDynamicInfo(BinaryReader reader) throws IOException {
		super(reader);
		bootstrap_method_attr_index = reader.readNextShort();
		name_and_type_index = reader.readNextShort();
	}

	/**
	 * The value of the bootstrap_method_attr_index item must be a valid index
	 * into the bootstrap_methods array of the bootstrap method table of
	 * this class file.
	 * @return a valid index into the bootstrap_methods array
	 */
	public int getBootstrapMethodAttrIndex() {
		return bootstrap_method_attr_index & 0xffff;
	}

	/**
	 * The value of the name_and_type_index item must be a valid index into
	 * the constant_pool table. The constant_pool entry at that index must be a
	 * CONSTANT_NameAndType_info structure representing a field descriptor.
	 * @return a valid index into the constant_pool table
	 */
	public int getNameAndTypeIndex() {
		return name_and_type_index & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "CONSTANT_Dynamic_info";
		Structure structure = new StructureDataType(name, 0);
		structure.add(BYTE, "tag", null);
		structure.add(WORD, "bootstrap_method_attr_index", null);
		structure.add(WORD, "name_and_type_index", null);
		return structure;

	}

}
