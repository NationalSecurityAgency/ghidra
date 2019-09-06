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
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * Each line_number_table entry must contain the following two items:
 * <pre>
 * 	LineNumber {
 * 		u2 start_pc;
 * 		u2 line_number;
 * 	}
 * </pre>
 */
public class LineNumber implements StructConverter {

	private short startPC;
	private short lineNumber;

	public LineNumber(BinaryReader reader) throws IOException {
		startPC = reader.readNextShort();
		lineNumber = reader.readNextShort();
	}

	/**
	 * The value of the start_pc item must indicate the index into the code array
	 * at which the code for a new line in the original source file begins.
	 * <p>
	 * The value of start_pc must be less than the value of the code_length
	 * item of the Code attribute of which this LineNumberTable is an attribute.
	 * @return index into the code array at which the code for a new line in the original source file begins
	 */
	public int getStartPC() {
		return startPC & 0xffff;
	}

	/**
	 * The value of the line_number item must give the corresponding line number in the original source file.
	 * @return the corresponding line number in the original source file
	 */
	public int getLineNumber() {
		return lineNumber & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = new StructureDataType("line_number", 0);
		structure.add(WORD, "start_pc", null);
		structure.add(WORD, "line_number", null);
		return structure;
	}

}
