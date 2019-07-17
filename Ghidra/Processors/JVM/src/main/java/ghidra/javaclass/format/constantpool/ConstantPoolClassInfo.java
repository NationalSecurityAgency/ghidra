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
 * The CONSTANT_Class_info structure is used to represent a class or an interface:
 * <pre>
 * CONSTANT_Class_info {
 *     u1 tag;
 *     u2 name_index;
 * }
 * </pre>
 * The items of the CONSTANT_Class_info structure are the following:
 * 	tag
 * 		The tag item has the value CONSTANT_Class (7).
 * 
 * name_index
 * 		The value of the name_index item must be a valid index into the
 * 		constant_pool table. The constant_pool entry at that index must be a
 * 		CONSTANT_Utf8_info (?4.4.7) structure representing a valid binary class or
 * 		interface name encoded in internal form (?4.2.1).
 */
public class ConstantPoolClassInfo extends AbstractConstantPoolInfoJava {

	private short nameIndex;

	public ConstantPoolClassInfo(BinaryReader reader) throws IOException {
		super(reader);

		nameIndex = reader.readNextShort();
	}

	/**
	 * The value of the name_index item must be a valid index into the
	 * constant_pool table. The constant_pool entry at that index must be a
	 * CONSTANT_Utf8_info (?4.4.7) structure representing a valid binary class or
	 * interface name encoded in internal form (?4.2.1).
	 * @return a valid index into the constant_pool table
	 */
	public int getNameIndex() {
		return nameIndex & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "CONSTANT_Class_info";
		Structure structure = new StructureDataType(name, 0);
		structure.add(BYTE, "tag", null);
		structure.add(WORD, "name_index", null);
		return structure;
	}

}
