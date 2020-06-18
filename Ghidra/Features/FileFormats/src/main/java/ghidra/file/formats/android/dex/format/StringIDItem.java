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

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://source.android.com/devices/tech/dalvik/dex-format#string-item
 */
public class StringIDItem implements StructConverter {

	private int stringDataOffset;
	private StringDataItem _stringDataItem;

	public StringIDItem(BinaryReader reader, DexHeader dexHeader) throws IOException {
		stringDataOffset = reader.readNextInt();
		try {
			_stringDataItem = new StringDataItem(this, reader, dexHeader);
		}
		catch (Exception e) {
			//ignore
			_stringDataItem =
				new StringDataItem("Invalid_String_0x" + Integer.toHexString(stringDataOffset));
		}
	}

	/**
	 * NOTE: For CDEX files, this value is relative to DataOffset in DexHeader
	 * @return the string data offset
	 */
	public int getStringDataOffset() {
		return stringDataOffset;
	}

	public StringDataItem getStringDataItem() {
		return _stringDataItem;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		DataType dataType = StructConverterUtil.toDataType(StringIDItem.class);
		dataType.setCategoryPath(new CategoryPath("/dex"));
		return dataType;
	}

}
