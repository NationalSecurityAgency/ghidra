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
import ghidra.javaclass.format.constantpool.ConstantPoolPackageInfo;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Note: text in this file based on/taken from jvms12.pdf
 * <p>
 * The {@code ModulePackages} attribute indicates all the packages of a module that are 
 * exported or opened by the {@code Module} attribute, as well as all the package of the service
 * implementations recorded in the {@code Module} attribute.
 */
public class ModulePackagesAttribute extends AbstractAttributeInfo {

	private short package_count;
	private short[] package_index;

	protected ModulePackagesAttribute(BinaryReader reader) throws IOException {
		super(reader);
		package_count = reader.readNextShort();
		package_index = new short[getPackageCount()];
		for (short i = 0; i < getPackageCount(); i++) {
			package_index[i] = reader.readNextShort();
		}
	}

	/**
	 * The value of the {@code package_count} item indicates the number of entries
	 * in the {@code package_index} table
	 * @return {@code package_index}
	 */
	public int getPackageCount() {
		return package_count & 0xffff;
	}

	/**
	 * The value of each entry in the {@code package_index} table must be a valid index
	 * into the constant pool. The entry at that index must be a {@link ConstantPoolPackageInfo} 
	 * structure representing a package in the current module.
	 * @param i entry
	 * @return package index
	 */
	public int getPackageIndexEntry(int i) {
		return package_index[i] & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = getBaseStructure("ModulePackages_attribute");
		structure.add(WORD, "package_count", null);
		for (int i = 0; i < package_index.length; ++i) {
			structure.add(WORD, "classes" + i, null);
		}
		return structure;
	}

}
