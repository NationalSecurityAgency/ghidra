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
import ghidra.javaclass.format.constantpool.ConstantPoolClassInfo;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Note: text taken from/based on jvms12.pdf
 * <p>
 * The {@code NestHost} attribute records the nest host of the next to which the current 
 * class or interface claims to belong.
 */
public class NestHostAttribute extends AbstractAttributeInfo {

	private short host_class_index;

	protected NestHostAttribute(BinaryReader reader) throws IOException {
		super(reader);
		host_class_index = reader.readNextShort();
	}

	/**
	 * The value of the {@code host_class_index} item must be a valid index into the constant
	 * pool. The entry at that index must be a {@link ConstantPoolClassInfo} structure representing
	 * a class or interface which is the nest host for the current class or interface.
	 * @return {@code host_class_index}
	 */
	public int getHostClassIndex() {
		return host_class_index & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = getBaseStructure("NestHost_attribute");
		structure.add(WORD, "host_class_index", null);
		return structure;
	}

}
