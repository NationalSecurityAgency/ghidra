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
package ghidra.file.formats.android.art;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/art/+/refs/heads/android10-release/runtime/art_field.h
 * 
 * NOTE: this class does not exist, was created to make field reading easier.
 */
public class ArtFieldGroup implements StructConverter {

	private int fieldCount;
	private List<ArtField> fieldList = new ArrayList<>();

	public ArtFieldGroup(BinaryReader reader) throws IOException {
		fieldCount = reader.readNextInt();
		if (fieldCount > 0xffff) {//sanity check...
			throw new IOException("Too many ART fields: " + fieldCount);
		}
		for (int i = 0; i < fieldCount; ++i) {
			fieldList.add(new ArtField(reader));
		}
	}

	public int getFieldCount() {
		return fieldCount;
	}

	public List<ArtField> getFieldList() {
		return fieldList;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = StructConverterUtil.parseName(ArtFieldGroup.class);
		Structure structure = new StructureDataType(name + "_" + fieldCount, 0);
		structure.setCategoryPath(new CategoryPath("/art"));
		structure.add(DWORD, "fieldCount", null);
		for (int i = 0; i < fieldCount; ++i) {
			structure.add(fieldList.get(i).toDataType(), "field_" + i, null);
		}
		return structure;
	}

}
