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
package ghidra.file.formats.android.vdex;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class VdexStringTable implements StructConverter {

	private int stringCount;//note only 1 byte in size
	private List<String> strings = new ArrayList<>();

	VdexStringTable(BinaryReader reader) throws IOException {
		stringCount = Byte.toUnsignedInt(reader.readNextByte());
		for (int i = 0; i < stringCount; ++i) {
			strings.add(reader.readNextAsciiString());
		}
	}

	public int getStringCount() {
		return stringCount;
	}

	public List<String> getStrings() {
		return strings;
	}

	public int getSize() {
		int size = 1;
		for (int i = 0; i < stringCount; ++i) {
			String string = strings.get(i);
			size += string.length() + 1;
		}
		return size;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String className = StructConverterUtil.parseName(VdexStringTable.class);
		Structure structure = new StructureDataType(className + "_" + stringCount, 0);
		structure.add(BYTE, "stringCount", null);
		for (int i = 0; i < stringCount; ++i) {
			String string = strings.get(i);
			structure.add(STRING, string.length() + 1, "string_" + i, null);
		}
		structure.setCategoryPath(new CategoryPath("/vdex"));
		return structure;
	}
}
