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
package ghidra.file.formats.android.art.android10;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

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
 * https://android.googlesource.com/platform/art/+/refs/heads/android10-release/runtime/image.h
 */
public class ArtHeader_10 extends ArtHeader {

	private int image_reservation_size_;
	private int component_count_;
	private int image_begin_;
	private int image_size_;
	private int image_checksum_;
	private int oat_checksum_;
	private int oat_file_begin_;
	private int oat_data_begin_;
	private int oat_data_end_;
	private int oat_file_end_;
	private int boot_image_begin_;
	private int boot_image_size_;
	private int image_roots_;
	private int pointer_size_;
	private long[] image_methods_ = new long[ImageMethod_10.kImageMethodsCount.ordinal()];
	private int data_size_;
	private int blocks_offset_;
	private int blocks_count_;
	private List<ArtBlock> blocks = new ArrayList<>();

	private ArtImageSections sections;

	public ArtHeader_10(BinaryReader reader) throws IOException {
		super(reader);
		parse(reader);
	}

	@Override
	protected void parse(BinaryReader reader) throws IOException {
		image_reservation_size_ = reader.readNextInt();
		component_count_ = reader.readNextInt();
		image_begin_ = reader.readNextInt();
		image_size_ = reader.readNextInt();
		image_checksum_ = reader.readNextInt();
		oat_checksum_ = reader.readNextInt();
		oat_file_begin_ = reader.readNextInt();
		oat_data_begin_ = reader.readNextInt();
		oat_data_end_ = reader.readNextInt();
		oat_file_end_ = reader.readNextInt();
		boot_image_begin_ = reader.readNextInt();
		boot_image_size_ = reader.readNextInt();
		image_roots_ = reader.readNextInt();
		pointer_size_ = reader.readNextInt();

		sections = new ImageSections_10(reader, this);
		sections.parseSections(reader);

		parseImageMethods(reader);

		data_size_ = reader.readNextInt();
		blocks_offset_ = reader.readNextInt();
		blocks_count_ = reader.readNextInt();

		if (blocks_offset_ > 0 && blocks_count_ > 0) {
			reader.setPointerIndex(blocks_offset_);
			for (int i = 0; i < blocks_count_; ++i) {
				blocks.add(new ArtBlock(reader));
			}
		}

		reader = DecompressionManager.decompress(reader, blocks, TaskMonitor.DUMMY);

		// NOTE:
		// cannot parse the sections until after the blocks are decompressed!

		sections.parse(reader);
	}

	@Override
	public int getArtMethodCountForVersion() {
		return ImageMethod_10.kImageMethodsCount.ordinal();
	}

	@Override
	public int getImageBegin() {
		return image_begin_;
	}

	@Override
	public int getImageSize() {
		return image_size_;
	}

	public int getImageChecksum_() {
		return image_checksum_;
	}

	@Override
	public int getOatChecksum() {
		return oat_checksum_;
	}

	@Override
	public int getOatDataBegin() {
		return oat_data_begin_;
	}

	@Override
	public int getOatDataEnd() {
		return oat_data_end_;
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
	public int getPointerSize() {
		return pointer_size_;
	}

	public int getBootImageBegin() {
		return boot_image_begin_;
	}

	/**
	 * App images currently require a boot image, 
	 * if the size is non zero then it is an app image header.
	 * @return true if this header represents an app image
	 */
	public boolean isAppImage() {
		return boot_image_size_ != 0x0;
	}

	public int getImageReservationSize() {
		return image_reservation_size_;
	}

	public int getComponentCount() {
		return component_count_;
	}

	public int getImageRoots() {
		return image_roots_;
	}

	public int getDataSize() {
		return data_size_;
	}

	public List<ArtBlock> getBlocks() {
		return blocks;
	}

	@Override
	public void markup(Program program, TaskMonitor monitor) throws Exception {
		DecompressionManager.decompressOverMemory(program, blocks, monitor);

		sections.markup(program, monitor);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = (Structure) super.toDataType();

		String className = StructConverterUtil.parseName(ArtHeader_10.class);
		try {
			structure.setName(className);
		}
		catch (InvalidNameException e) {
			//ignore, just use original name should this fail
		}

		structure.add(DWORD, "image_reservation_size_", null);
		structure.add(DWORD, "component_count_", null);
		structure.add(DWORD, "image_begin_", null);
		structure.add(DWORD, "image_size_", null);
		structure.add(DWORD, "image_checksum_", null);
		structure.add(DWORD, "oat_checksum_", null);
		structure.add(DWORD, "oat_file_begin_", null);
		structure.add(DWORD, "oat_data_begin_", null);
		structure.add(DWORD, "oat_data_end_", null);
		structure.add(DWORD, "oat_file_end_", null);
		structure.add(DWORD, "boot_image_begin_", null);
		structure.add(DWORD, "boot_image_size_", null);
		structure.add(DWORD, "image_roots_", null);
		structure.add(DWORD, "pointer_size_", null);

		for (int i = 0; i < sections.getSectionList().size(); ++i) {
			structure.add(sections.getSectionList().get(i).toDataType(), "section_" + i, null);
		}
		for (int i = 0; i < image_methods_.length; ++i) {
			structure.add(QWORD, "image_method_" + i, null);
		}

		structure.add(DWORD, "data_size_", null);
		structure.add(DWORD, "blocks_offset_", null);
		structure.add(DWORD, "blocks_count_", null);
		return structure;
	}
}
