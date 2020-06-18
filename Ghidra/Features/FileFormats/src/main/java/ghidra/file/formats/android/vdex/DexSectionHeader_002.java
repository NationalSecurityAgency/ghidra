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
package ghidra.file.formats.android.vdex;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/art/+/refs/heads/pie-release/runtime/vdex_file.h#114
 */
public class DexSectionHeader_002 implements StructConverter {

	private int dex_size_;
	private int dex_shared_data_size_;
	private int quickening_info_size_;

	DexSectionHeader_002(BinaryReader reader) throws IOException {
		dex_size_ = reader.readNextInt();
		dex_shared_data_size_ = reader.readNextInt();
		quickening_info_size_ = reader.readNextInt();
	}

	public int getDexSize() {
		return dex_size_;
	}

	public int getDexSharedDataSize() {
		return dex_shared_data_size_;
	}

	public int getQuickeningInfoSize() {
		return quickening_info_size_;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		DataType dataType = StructConverterUtil.toDataType(DexSectionHeader_002.class);
		dataType.setCategoryPath(new CategoryPath("/vdex"));
		return dataType;
	}

}
