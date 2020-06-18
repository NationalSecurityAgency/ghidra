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
package ghidra.file.formats.android.dex.format;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.*;

public class TypeList implements StructConverter {

	private int size;
	private List<TypeItem> items = new ArrayList<TypeItem>();

	public TypeList(BinaryReader reader) throws IOException {
		size = reader.readNextInt();
		for (int i = 0; i < size; ++i) {
			items.add(new TypeItem(reader));
		}
	}

	/**
	 * Size of the list, in entries
	 */
	public int getSize() {
		return size;
	}

	/**
	 * Elements of the list
	 */
	public List<TypeItem> getItems() {
		return Collections.unmodifiableList(items);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("type_list" + size, 0);
		structure.add(DWORD, "size", null);
		int index = 0;
		for (TypeItem item : items) {
			structure.add(item.toDataType(), "item_" + (index++), null);
		}
		structure.setCategoryPath(new CategoryPath("/dex"));
		return structure;
	}

}
