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
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * The Exceptions attribute is a variable-length attribute in the attributes table of a
 * method_info structure. The Exceptions attribute indicates which checked
 * exceptions a method may throw. There may be at most one Exceptions attribute
 * in each method_info structure.
 * <p>
 * The Exceptions attribute has the following format:
 * <pre>
 * 	Exceptions_attribute {
 * 		u2 attribute_name_index;
 * 		u4 attribute_length;
 * 		u2 number_of_exceptions;
 * 		u2 exception_index_table[number_of_exceptions];
 * 	}
 * </pre>
 */
public class ExceptionsAttribute extends AbstractAttributeInfo {

	private short numberOfExceptions;
	private short[] exceptionIndexTable;

	public ExceptionsAttribute(BinaryReader reader) throws IOException {
		super(reader);

		numberOfExceptions = reader.readNextShort();
		exceptionIndexTable = reader.readNextShortArray(getNumberOfExceptions());
	}

	/**
	 * The value of the number_of_exceptions item indicates the number of entries
	 * in the exception_index_table.
	 * @return the number of entries in the exception_index_table
	 */
	public int getNumberOfExceptions() {
		return numberOfExceptions & 0xffff;
	}

	/**
	 * Each value in the exception_index_table array must be a valid index into
	 * the constant_pool table. The constant_pool entry referenced by each table
	 * item must be a CONSTANT_Class_info structure representing a class
	 * type that this method is declared to throw.
	 * @param i entry
	 * @return index
	 */
	public int getExceptionIndexTableEntry(int i) {
		return exceptionIndexTable[i] & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = getBaseStructure("Exceptions_attribute");
		structure.add(WORD, "number_of_exceptions", null);
		if (exceptionIndexTable.length > 0) {
			DataType array = new ArrayDataType(WORD, exceptionIndexTable.length, WORD.getLength());
			structure.add(array, "exception_index_table", null);
		}
		return structure;
	}

}
