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
import ghidra.javaclass.format.constantpool.AbstractConstantPoolInfoJava;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * The LocalVariableTable attribute is an optional variable-length attribute in the
 * attributes table of a Code attribute. It may be used by debuggers to
 * determine the value of a given local variable during the execution of a method.
 * <p>
 * If LocalVariableTable attributes are present in the attributes table of a given
 * Code attribute, then they may appear in any order. There may be no more than one
 * LocalVariableTable attribute per local variable in the Code attribute.
 * <p>
 * The LocalVariableTable attribute has the following format:
 * <pre>
 * 	LocalVariableTable_attribute {
 * 		u2 attribute_name_index;
 * 		u4 attribute_length;
 * 		u2 local_variable_table_length;
 * 		{
 * 			u2 start_pc;
 * 			u2 length;
 * 			u2 name_index;
 * 			u2 descriptor_index;
 * 			u2 index;
 * 		} local_variable_table[local_variable_table_length];
 * 	}
 * </pre>
 */
public class LocalVariableTableAttribute extends AbstractAttributeInfo {

	private short localVariableTableLength;
	private LocalVariableJava[] localVariableTable;

	public LocalVariableTableAttribute(BinaryReader reader,
			AbstractConstantPoolInfoJava[] constantPool) throws IOException {
		super(reader);

		localVariableTableLength = reader.readNextShort();
		localVariableTable = new LocalVariableJava[localVariableTableLength & 0xffff];
		for (int i = 0; i < (localVariableTableLength & 0xffff); i++) {
			localVariableTable[i] = new LocalVariableJava(reader);
		}
	}

	public LocalVariableJava[] getLocalVariables() {
		return localVariableTable;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = getBaseStructure("LocalVariableTable_attribute");
		structure.add(WORD, "local_variable_table_length", null);
		for (int i = 0; i < localVariableTable.length; ++i) {
			structure.add(localVariableTable[i].toDataType(), "local_variable_" + i, null);
		}
		return structure;
	}

}
