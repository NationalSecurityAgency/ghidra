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

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/art/+/refs/heads/android10-release/runtime/image.h
 * 
 *
 */
public class ArtBlock implements StructConverter, ArtCompression {

	private ArtStorageMode storage_mode_ = ArtStorageMode.kDefaultStorageMode;
	private int data_offset_;
	private int data_size_;
	private int image_offset_;
	private int image_size_;

	public ArtBlock(BinaryReader reader) throws IOException {
		storage_mode_ = ArtStorageMode.get(reader.readNextInt());
		data_offset_ = reader.readNextInt();
		data_size_ = reader.readNextInt();
		image_offset_ = reader.readNextInt();
		image_size_ = reader.readNextInt();
	}

	@Override
	public ArtStorageMode getStorageMode() {
		return storage_mode_;
	}

	@Override
	public long getCompressedOffset() {
		return Integer.toUnsignedLong(data_offset_);
	}

	@Override
	public int getCompressedSize() {
		return data_size_;
	}

	@Override
	public long getDecompressedOffset() {
		return Integer.toUnsignedLong(image_offset_);
	}

	@Override
	public int getDecompressedSize() {
		return image_size_;
	}

	public int getDataOffset() {
		return data_offset_;
	}

	public int getDataSize() {
		return data_size_;
	}

	public int getImageOffset() {
		return image_offset_;
	}

	public int getImageSize() {
		return image_size_;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = StructConverterUtil.parseName(ArtBlock.class);
		Structure structure = new StructureDataType(name, 0);
		structure.setCategoryPath(new CategoryPath("/art"));
		structure.add(DWORD, "storage_mode_", storage_mode_.name());
		structure.add(DWORD, "data_offset_", null);
		structure.add(DWORD, "data_size_", null);
		structure.add(DWORD, "image_offset_", null);
		structure.add(DWORD, "image_size_", null);
		return structure;
	}

}
