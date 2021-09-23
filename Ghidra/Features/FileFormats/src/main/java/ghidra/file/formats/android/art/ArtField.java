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

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/art/+/refs/heads/android10-release/runtime/art_field.h
 * 
 *
 */
public class ArtField implements StructConverter {

	private int declaring_class_;
	private int access_flags_;
	private int field_dex_idx_;
	private int offset_;

	public ArtField(BinaryReader reader) throws IOException {
		declaring_class_ = reader.readNextInt();
		access_flags_ = reader.readNextInt();
		field_dex_idx_ = reader.readNextInt();
		offset_ = reader.readNextInt();
	}

	public int getDeclaringClass() {
		return declaring_class_;
	}

	public int getAccessFlags() {
		return access_flags_;
	}

	public int getFieldDexIndex() {
		return field_dex_idx_;
	}

	public int getOffset() {
		return offset_;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = StructConverterUtil.parseName(ArtField.class);
		Structure structure = new StructureDataType(name, 0);
		structure.setCategoryPath(new CategoryPath("/art"));
		structure.add(new Pointer32DataType(), "declaring_class_", null);
		structure.add(DWORD, "access_flags_", null);
		structure.add(DWORD, "field_dex_idx_", null);
		structure.add(DWORD, "offset_", null);
		return structure;
	}

}
