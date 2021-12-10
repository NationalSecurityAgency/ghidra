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
package ghidra.file.formats.android.oat.oatdexfile;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.android.oat.bundle.OatBundle;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * 
 * https://android.googlesource.com/platform/art/+/refs/heads/oreo-release/runtime/oat_file.h#444
 */
class OatDexFile_Oreo extends OatDexFile_Nougat {

	OatDexFile_Oreo(BinaryReader reader, OatBundle bundle) throws IOException {
		super(reader);
		dexHeader = bundle.getDexHeaderByChecksum(dex_file_location_checksum_);
	}

	@Override
	public boolean isDexHeaderExternal() {
		return true;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		DataType dataType = super.toDataType();
		try {
			dataType.setName(OatDexFile_Oreo.class.getSimpleName() + "_" +
				"_" + Integer.toHexString(dex_file_location_));
		}
		catch (Exception e) {
			//ignore
		}
		return dataType;
	}
}
