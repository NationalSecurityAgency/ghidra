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
package ghidra.app.util.bin.format.omf;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class OmfString implements StructConverter {

	private int length;
	private String str;

	public OmfString(int length, String str) {
		this.length = length;
		this.str = str;
	}

	public int length() {
		return length;
	}

	public String str() {
		return str;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		if (length == 0) {
			return BYTE;
		}

		StructureDataType struct = new StructureDataType("OmfString", 0);
		struct.add(BYTE, "length", "");
		struct.add(new StringDataType(), length, "str", null);
		struct.setCategoryPath(new CategoryPath(OmfRecord.CATEGORY_PATH));
		return struct;
	}
}
