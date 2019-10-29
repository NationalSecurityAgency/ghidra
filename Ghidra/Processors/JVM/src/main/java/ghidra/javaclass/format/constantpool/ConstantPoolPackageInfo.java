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
 * Note: text taken from/based on jvms12.pdf
 * <p>
 * Objects of this class represent a package exported or opened by a module
 */
public class ConstantPoolPackageInfo extends AbstractConstantPoolInfoJava {

	private short name_index;

	protected ConstantPoolPackageInfo(BinaryReader reader) throws IOException {
		super(reader);
		name_index = reader.readNextShort();
	}

	/**
	 * The {@code name_index} must be a valid index into the constant pool. The entry at that index
	 * must be a {@link ConstantPoolUtf8Info} structure representing a valid package name (encoded 
	 * in internal form).
	 * @return the name index
	 */
	public int getNameIndex() {
		return name_index & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "CONSTANT_Package_info";
		Structure structure = new StructureDataType(name, 0);
		structure.add(BYTE, "tag", null);
		structure.add(WORD, "name_index", null);
		return structure;
	}

}
