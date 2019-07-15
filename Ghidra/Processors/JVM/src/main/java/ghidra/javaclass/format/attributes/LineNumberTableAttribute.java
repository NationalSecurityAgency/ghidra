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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * The LineNumberTable attribute is an optional variable-length attribute in the
 * attributes table of a Code attribute. It may be used by debuggers to
 * determine which part of the Java virtual machine code array corresponds to a given
 * line number in the original source file.
 * 
 * If LineNumberTable attributes are present in the attributes table of a given
 * Code attribute, then they may appear in any order. Furthermore, multiple
 * LineNumberTable attributes may together represent a given line of a source file;
 * that is, LineNumberTable attributes need not be one-to-one with source lines.
 * 
 * The LineNumberTable attribute has the following format:
 * <pre>
 * 	LineNumberTable_attribute {
 * 		u2 attribute_name_index;
 * 		u4 attribute_length;
 * 		u2 line_number_table_length;
 * 		{
 * 			u2 start_pc;
 * 			u2 line_number;
 * 		} line_number_table[line_number_table_length];
 * 	}
 * </pre>
 */
public class LineNumberTableAttribute extends AbstractAttributeInfo {

	private short lineNumberTableLength;
	private LineNumber[] lineNumberTable;

	public LineNumberTableAttribute(BinaryReader reader) throws IOException {
		super(reader);

		lineNumberTableLength = reader.readNextShort();
		lineNumberTable = new LineNumber[lineNumberTableLength & 0xffff];
		for (int i = 0; i < (lineNumberTableLength & 0xffff); i++) {
			lineNumberTable[i] = new LineNumber(reader);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = "LineNumberTable_attribute" + "|" + lineNumberTableLength + "|";
		StructureDataType structure = getBaseStructure(name);
		structure.add(WORD, "line_number_table_length", null);
		for (int i = 0; i < lineNumberTable.length; ++i) {
			structure.add(lineNumberTable[i].toDataType(), "line_number_" + i, null);
		}
		return structure;
	}

}
