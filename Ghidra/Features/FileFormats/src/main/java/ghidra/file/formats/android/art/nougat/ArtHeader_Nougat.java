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
package ghidra.file.formats.android.art.nougat;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.file.formats.android.art.*;
import ghidra.file.formats.android.util.DecompressionManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * https://android.googlesource.com/platform/art/+/nougat-release/runtime/image.h
 * https://android.googlesource.com/platform/art/+/nougat-release/runtime/image.cc
 */
public class ArtHeader_Nougat extends ArtHeader implements ArtCompression {

	protected int image_begin_;
	protected int image_size_;
	protected int oat_checksum_;
	protected int oat_file_begin_;
	protected int oat_data_begin_;
	protected int oat_data_end_;
	protected int oat_file_end_;
	protected int boot_image_begin_;
	protected int boot_image_size_;
	protected int boot_oat_begin_;
	protected int boot_oat_size_;
	protected int patch_delta_;
	protected int image_roots_;
	protected int pointer_size_;
	protected int compile_pic_;
	protected int is_pic_;
	protected int storage_mode_;
	protected int data_size_;

	protected ArtImageSections sections;

	private long _compressedOffset;

	public ArtHeader_Nougat(BinaryReader reader) throws IOException {
		super(reader);
		parse(reader);
	}

	protected ArtImageSections getImageSections(BinaryReader reader) {
		return new ImageSections_Nougat(reader, this);
	}

	@Override
	protected void parse(BinaryReader reader) throws IOException {
		image_begin_ = reader.readNextInt();
		image_size_ = reader.readNextInt();
		oat_checksum_ = reader.readNextInt();
		oat_file_begin_ = reader.readNextInt();
		oat_data_begin_ = reader.readNextInt();
		oat_data_end_ = reader.readNextInt();
		oat_file_end_ = reader.readNextInt();
		boot_image_begin_ = reader.readNextInt();
		boot_image_size_ = reader.readNextInt();
		boot_oat_begin_ = reader.readNextInt();
		boot_oat_size_ = reader.readNextInt();
		patch_delta_ = reader.readNextInt();
		image_roots_ = reader.readNextInt();
		pointer_size_ = reader.readNextInt();
		compile_pic_ = reader.readNextInt();
		is_pic_ = reader.readNextInt();

		sections = getImageSections(reader);

		sections.parseSections(reader);
		parseImageMethods(reader);

		storage_mode_ = reader.readNextInt();
		data_size_ = reader.readNextInt();

		//The compressed offset is immediately following this header.
		_compressedOffset = reader.getPointerIndex();

		reader = DecompressionManager.decompress(reader, this, TaskMonitor.DUMMY);

		sections.parse(reader);
	}

	@Override
	public int getArtMethodCountForVersion() {
		return ImageMethod_Nougat.kImageMethodsCount.ordinal();
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
	 * Boot oat begin and end (app image headers only).
	 * @return the boot oat begin address
	 */
	public int getBootOatBegin() {
		return boot_oat_begin_;
	}

	/**
	 * Boot oat begin and end (app image headers only).
	 * @return the boot oat size
	 */
	public int getBootOatSize() {
		return boot_oat_size_;
	}

	@Override
	public int getOatFileBegin() {
		return oat_file_begin_;
	}

	@Override
	public int getOatFileEnd() {
		return oat_file_end_;
	}

	@Override
	public int getOatDataBegin() {
		return oat_data_begin_;
	}

	@Override
	public int getOatDataEnd() {
		return oat_data_end_;
	}

	/**
	 * Boolean (0 or 1) to denote if the image can be mapped at a random address, 
	 * this only refers to the .art file. 
	 * Currently, app oat files do not depend on their app image. 
	 * There are no pointers from the app oat code to the app image.
	 * @return true of position independent code, or false if dependent.
	 */
	public int getIsPic() {
		return is_pic_;
	}

	@Override
	public ArtStorageMode getStorageMode() throws UnknownArtStorageModeException {
		return ArtStorageMode.get(storage_mode_);
	}

	@Override
	public long getCompressedOffset() {
		return _compressedOffset;
	}

	@Override
	public int getCompressedSize() {
		return data_size_;
	}

	@Override
	public long getDecompressedOffset() {
		return getCompressedOffset();
	}

	@Override
	public int getDecompressedSize() {
		return image_size_;
	}

	/**
	 * Checksum of the oat file we link to for load time sanity check.
	 */
	@Override
	public int getOatChecksum() {
		return oat_checksum_;
	}

	@Override
	public int getPointerSize() {
		return pointer_size_;
	}

	@Override
	public void markup(Program program, TaskMonitor monitor) throws Exception {
		DecompressionManager.decompressOverMemory(program, this, monitor);

		sections.markup(program, monitor);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = (Structure) super.toDataType();

		String className = StructConverterUtil.parseName(ArtHeader_Nougat.class);
		try {
			structure.setName(className);
		}
		catch (InvalidNameException e) {
			//ignore, just use original name should this fail
		}

		structure.add(DWORD, "image_begin_", null);
		structure.add(DWORD, "image_size_", null);
		structure.add(DWORD, "oat_checksum_", null);
		structure.add(DWORD, "oat_file_begin_", null);
		structure.add(DWORD, "oat_data_begin_", null);
		structure.add(DWORD, "oat_data_end_", null);
		structure.add(DWORD, "oat_file_end_", null);
		structure.add(DWORD, "boot_image_begin_", null);
		structure.add(DWORD, "boot_image_size_", null);
		structure.add(DWORD, "boot_oat_begin_", null);
		structure.add(DWORD, "boot_oat_size_", null);
		structure.add(DWORD, "patch_delta_", null);
		structure.add(DWORD, "image_roots_", null);
		structure.add(DWORD, "pointer_size_", null);
		structure.add(DWORD, "compile_pic_", null);
		structure.add(DWORD, "is_pic_", null);

		for (int i = 0; i < sections.getSectionList().size(); ++i) {
			structure.add(sections.getSectionList().get(i).toDataType(), "section_" + i, null);
		}
		for (int i = 0; i < imageMethodsList.size(); ++i) {
			structure.add(QWORD, "image_method_" + i, null);
		}
		structure.add(DWORD, "storage_mode_", null);
		structure.add(DWORD, "data_size_", null);
		return structure;
	}

}
