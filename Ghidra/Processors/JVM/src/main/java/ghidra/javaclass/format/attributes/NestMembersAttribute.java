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
 * The {@NestMembers} attribute records the classes and interfaces that are authorized to 
 * claim membership in the nest hosted by the current class or interface.
 */
public class NestMembersAttribute extends AbstractAttributeInfo {

	private short number_of_classes;
	private short[] classes;

	protected NestMembersAttribute(BinaryReader reader) throws IOException {
		super(reader);
		number_of_classes = reader.readNextShort();
		classes = new short[getNumberOfClasses()];
		for (short i = 0; i < getNumberOfClasses(); i++) {
			classes[i] = reader.readNextShort();
		}
	}

	/**
	 * The value of the {@code number_of_classes} item indicates the number of entries in
	 * the {@code classes} array.
	 * @return {@code number_of_classes}
	 */
	public int getNumberOfClasses() {
		return number_of_classes & 0xffff;
	}

	/**
	 * Each value in the {@code classes} array must be a valid index into the constant pool.
	 * The constant pool entry at that index must be a {@link ConstantPoolClassInfo} structure
	 * representing a class or interface which is a member of the nest hosted by the current
	 * class or interface.
	 * @param i entry
	 * @return class index
	 */
	public int getClassesEntry(int i) {
		return classes[i] & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = getBaseStructure("NestMembers_attribute");
		structure.add(WORD, "number_of_classes", null);
		for (int i = 0; i < classes.length; ++i) {
			structure.add(WORD, "classes" + i, null);
		}
		return structure;
	}

}
