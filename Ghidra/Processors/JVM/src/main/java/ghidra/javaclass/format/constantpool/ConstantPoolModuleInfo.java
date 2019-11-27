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
 * Note: text in comments taken from/based on jvms12.pdf
 * <p>
 * The {@code CONSTANT_Module_info} structure is used to represent a module.
 */
public class ConstantPoolModuleInfo extends AbstractConstantPoolInfoJava {

	private short name_index;

	protected ConstantPoolModuleInfo(BinaryReader reader) throws IOException {
		super(reader);
		name_index = reader.readNextShort();
	}

	/**
	 * The value of the {@code name_index} item must be a valid index into the constant pool.
	 * The entry at that index must be a {@link ConstantPoolUtf8Info} structure representing a 
	 * valid module name.
	 * @return the module name index
	 */
	public int getNameIndex() {
		return name_index & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "CONSTANT_Module_info";
		Structure structure = new StructureDataType(name, 0);
		structure.add(BYTE, "tag", null);
		structure.add(WORD, "name_index", null);
		return structure;
	}

}
