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
 * The SourceFile attribute is an optional fixed-length attribute in the attributes
 * table of a ClassFile structure. There can be no more than one SourceFile
 * attribute in the attributes table of a given ClassFile structure.
 * <p>
 * The SourceFile attribute has the following format:
 * <pre>
 * 	SourceFile_attribute {
 * 		u2 attribute_name_index;
 * 		u4 attribute_length;
 * 		u2 sourcefile_index;
 * 	}
 * </pre>
 */
public class SourceFileAttribute extends AbstractAttributeInfo {

	private short sourceFileIndex;

	public SourceFileAttribute(BinaryReader reader) throws IOException {
		super(reader);

		sourceFileIndex = reader.readNextShort();
	}

	/**
	 * The value of the sourcefile_index item must be a valid index into the
	 * constant_pool table. The constant pool entry at that index must be a
	 * CONSTANT_Utf8_info structure representing a string.
	 * <p>
	 * The string referenced by the sourcefile_index item will be interpreted as
	 * indicating the name of the source file from which this class file was compiled.
	 * It will not be interpreted as indicating the name of a directory containing the
	 * file or an absolute path name for the file; such platform-specific additional
	 * information must be supplied by the runtime interpreter or development tool
	 * at the time the file name is actually used.
	 * @return a valid index into the constant_pool table
	 */
	public int getSourceFileIndex() {
		return sourceFileIndex & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType structure = getBaseStructure("SourceFile_attribute");
		structure.add(WORD, "sourcefile_index", null);
		return structure;
	}

}
