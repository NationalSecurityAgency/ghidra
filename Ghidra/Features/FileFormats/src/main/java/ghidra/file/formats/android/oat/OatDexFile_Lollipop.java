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
package ghidra.file.formats.android.oat;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Note: actual data structure seen in firmware does not contain the "canonical_dex_file_location_" field.
 * 
 * https://android.googlesource.com/platform/art/+/refs/heads/lollipop-release/runtime/oat_file.h#261
 */
class OatDexFile_Lollipop extends OatDexFile_KitKat {

	OatDexFile_Lollipop(BinaryReader reader) throws IOException {
		super(reader);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		DataType dataType = super.toDataType();
		try {
			dataType.setName(StructConverterUtil.parseName(OatDexFile_Lollipop.class) + "_" +
				oat_class_offsets_pointer_.length);
		}
		catch (Exception e) {
			//ignore
		}
		return dataType;
	}

}
