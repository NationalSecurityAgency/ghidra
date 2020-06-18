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
package ghidra.file.formats.android.prof;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * <code>
 * profile_header:
 *	magic (4)
 *	version (4)
 *	number_of_dex_files (1)
 *	uncompressed_size_of_zipped_data (4)
 *	compressed_data_size (4)
 *	compressed data in 0x78 0x01 format
 * </code>
 */
public class ProfileHeader implements StructConverter {
	private byte[] magic;
	private byte[] version;
	private byte number_of_dex_files;
	private int uncompressed_size_of_zipped_data;
	private int compressed_data_size;
	private int _compressed_data_offset;

	public ProfileHeader(BinaryReader reader) throws IOException {
		magic = reader.readNextByteArray(ProfileConstants.kProfileMagic.length);
		version = reader.readNextByteArray(ProfileConstants.kProfileVersion_008.length);
		number_of_dex_files = reader.readNextByte();
		uncompressed_size_of_zipped_data = reader.readNextInt();
		compressed_data_size = reader.readNextInt();
		_compressed_data_offset = (int) reader.getPointerIndex();
	}

	public String getMagic() {
		return new String(magic).trim();
	}

	public String getVersion() {
		return new String(version).trim();
	}

	public byte getNumberOfDexFiles() {
		return number_of_dex_files;
	}

	public int getUncompressedSizeOfZippedData() {
		return uncompressed_size_of_zipped_data;
	}

	public int getCompressedDataSize() {
		return compressed_data_size;
	}

	public int getCompressedDataOffset() {
		return _compressed_data_offset;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(ProfileHeader.class);
	}

}
