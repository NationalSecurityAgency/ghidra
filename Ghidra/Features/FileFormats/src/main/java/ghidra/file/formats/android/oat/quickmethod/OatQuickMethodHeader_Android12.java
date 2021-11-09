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
package ghidra.file.formats.android.oat.quickmethod;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/art/+/refs/heads/android-s-beta-5/runtime/oat_quick_method_header.h#160
 *
 */
public class OatQuickMethodHeader_Android12 extends OatQuickMethodHeader {

	public static final int kShouldDeoptimizeMask = 0x80000000;
	public static final int kIsCodeInfoMask = 0x40000000;
	public static final int kCodeInfoMask = 0x3FFFFFFF;  // If kIsCodeInfoMask is set.
	public static final int kCodeSizeMask = 0x3FFFFFFF;  // If kIsCodeInfoMask is clear.

	private int data_;

	OatQuickMethodHeader_Android12(BinaryReader reader) throws IOException {
		data_ = reader.readNextInt();
	}

	public int getData() {
		return data_;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure =
			new StructureDataType(OatQuickMethodHeader_Android12.class.getSimpleName(), 0);
		structure.add(DWORD, "data_", null);
		structure.setCategoryPath(new CategoryPath("/oat"));
		return structure;
	}

	@Override
	public int getCodeSize() {
		return data_ & kCodeSizeMask;
	}

}
