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
package ghidra.file.formats.android.oat.tlt;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/android12-release/libdexfile/dex/type_lookup_table.h#35">android12-release/libdexfile/dex/type_lookup_table.h</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/android13-release/libdexfile/dex/type_lookup_table.h#35">android13-release/libdexfile/dex/type_lookup_table.h</a>
 */
public class TypeLookupTable_S_T extends TypeLookupTable_Q {

	public TypeLookupTable_S_T(BinaryReader reader) throws IOException {
		super(reader);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		DataType dataType = super.toDataType();
		try {
			dataType.setName(
				TypeLookupTable_S_T.class.getSimpleName() + "_" + entryList.size());
		}
		catch (Exception e) {
			//ignore
		}
		return dataType;
	}

}
