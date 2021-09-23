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
 * https://android.googlesource.com/platform/art/+/refs/heads/android10-release/runtime/art_method.h
 * 
 * NOTE: this class does not exist, was created to make method reading easier.
 */
public class ArtMethodGroup implements StructConverter {

	private int pointerSize;

	private long methodCount;
	private List<ArtMethod> methodList = new ArrayList<>();

	public ArtMethodGroup(BinaryReader reader, int pointerSize, String artVersion)
			throws IOException {
		this.pointerSize = pointerSize;

		if (pointerSize == 8) {
			methodCount = reader.readNextLong();
		}
		else if (pointerSize == 4) {
			methodCount = Integer.toUnsignedLong(reader.readNextInt());
		}

		if (methodCount > 0xffff) {//sanity check...
			throw new IOException("Too many ART methods: " + methodCount);
		}

		for (int i = 0; i < methodCount; ++i) {
			methodList.add(new ArtMethod(reader, pointerSize, artVersion));
		}
	}

	public long getMethodCount() {
		return methodCount;
	}

	public List<ArtMethod> getMethodList() {
		return methodList;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = StructConverterUtil.parseName(ArtMethodGroup.class);
		Structure structure = new StructureDataType(name + "_" + methodCount, 0);
		structure.setCategoryPath(new CategoryPath("/art"));
		if (pointerSize == 8) {
			structure.add(QWORD, "methodCount", null);
		}
		else if (pointerSize == 4) {
			structure.add(DWORD, "methodCount", null);
		}
		for (int i = 0; i < methodCount; ++i) {
			structure.add(methodList.get(i).toDataType(), "method_" + i, null);
		}
		return structure;
	}

}
