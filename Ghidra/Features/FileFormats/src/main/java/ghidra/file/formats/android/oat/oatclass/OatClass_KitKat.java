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
package ghidra.file.formats.android.oat.oatclass;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.android.dex.format.ClassDataItem;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/kitkat-release/runtime/oat_file.h#156">kitkat-release/runtime/oat_file.h</a>
 */
public class OatClass_KitKat extends OatClass {

	private int methods_pointer_;

	public OatClass_KitKat(BinaryReader reader, ClassDataItem classDataItem, String oatVersion)
			throws IOException {

		super(reader, oatVersion);
		methods_pointer_ = reader.readNextInt();
	}

	public int getMethodsPointer() {
		return methods_pointer_;
	}

	@Override
	public boolean isMethodNative(int methodIndex) {
		return false;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(OatClass_KitKat.class.getSimpleName(), 0);
		structure.add(statusEnum.toDataType(), "status_", null);
		structure.add(DWORD, "methods_pointer_", null);
		structure.setCategoryPath(new CategoryPath("/oat"));
		return structure;
	}

}
