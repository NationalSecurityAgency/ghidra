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
package ghidra.file.formats.android.art.kitkat;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.file.formats.android.art.ArtHeader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * @see https://android.googlesource.com/platform/art/+/refs/heads/kitkat-release/runtime/image.cc
 */
public class ArtHeader_KitKat extends ArtHeader {

	protected int image_begin_;
	protected int image_size_;
	protected int image_bitmap_offset_;
	protected int image_bitmap_size_;
	protected int oat_checksum_;
	protected int oat_file_begin_;
	protected int oat_data_begin_;
	protected int oat_data_end_;
	protected int oat_file_end_;
	protected int image_roots_;

	public ArtHeader_KitKat(BinaryReader reader) throws IOException {
		super(reader);
		parse(reader);
	}

	@Override
	protected void parse(BinaryReader reader) throws IOException {
		image_begin_ = reader.readNextInt();
		image_size_ = reader.readNextInt();
		image_bitmap_offset_ = reader.readNextInt();
		image_bitmap_size_ = reader.readNextInt();
		oat_checksum_ = reader.readNextInt();
		oat_file_begin_ = reader.readNextInt();
		oat_data_begin_ = reader.readNextInt();
		oat_data_end_ = reader.readNextInt();
		oat_file_end_ = reader.readNextInt();
		image_roots_ = reader.readNextInt();
	}

	@Override
	public int getImageBegin() {
		return image_begin_;
	}

	@Override
	public int getImageSize() {
		return image_size_;
	}

	/**
	 * Image bitmap offset in the file.
	 */
	public int getImageBitmapOffset() {
		return image_bitmap_offset_;
	}

	/**
	 * Size of the image bitmap.
	 */
	public int getImageBitmapSize() {
		return image_bitmap_size_;
	}

	/**
	 * Checksum of the oat file we link to for load time sanity check.
	 */
	public int getOatChecksum() {
		return oat_checksum_;
	}

	/**
	 * Start address for oat file. Will be before oat_data_begin_ for .so files.
	 */
	@Override
	public int getOatFileBegin() {
		return oat_file_begin_;
	}

	/**
	 * Required oat address expected by image Method::GetCode() pointers.
	 */
	@Override
	public int getOatDataBegin() {
		return oat_data_begin_;
	}

	/**
	 * End of oat data address range for this image file.
	 */
	@Override
	public int getOatDataEnd() {
		return oat_data_end_;
	}

	/**
	 * End of oat file address range. will be after oat_data_end_ for 
	 * .so files. Used for positioning a following alloc spaces.
	 */
	@Override
	public int getOatFileEnd() {
		return oat_file_end_;
	}

	/**
	 * Absolute address of an Object[] of objects needed to reinitialize from an image.
	 */
	public int getImageRoots() {
		return image_roots_;
	}

	@Override
	public int getPointerSize() {
		return -1; //unsupported
	}

	@Override
	public void markup(Program program, TaskMonitor monitor) throws Exception {
		//do nothing for now
	}

	@Override
	public int getArtMethodCountForVersion() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = (Structure) super.toDataType();

		String className = StructConverterUtil.parseName(ArtHeader_KitKat.class);
		try {
			structure.setName(className);
		}
		catch (InvalidNameException e) {
		}

		structure.add(DWORD, "image_begin_", null);
		structure.add(DWORD, "image_size_", null);
		structure.add(DWORD, "image_bitmap_offset_", null);
		structure.add(DWORD, "image_bitmap_size_", null);
		structure.add(DWORD, "oat_checksum_", null);
		structure.add(DWORD, "oat_file_begin_", null);
		structure.add(DWORD, "oat_data_begin_", null);
		structure.add(DWORD, "oat_data_end_", null);
		structure.add(DWORD, "oat_file_end_", null);
		structure.add(DWORD, "image_roots_", null);

		return structure;
	}

}
