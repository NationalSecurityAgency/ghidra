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
package ghidra.file.formats.android.art.marshmallow;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.file.formats.android.art.ArtHeader;
import ghidra.file.formats.android.art.ArtImageSections;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * @see https://android.googlesource.com/platform/art/+/marshmallow-release/runtime/image.h
 */
public class ArtHeader_Marshmallow extends ArtHeader {

	protected int image_begin_;
	protected int image_size_;
	protected int oat_checksum_;
	protected int oat_file_begin_;
	protected int oat_data_begin_;
	protected int oat_data_end_;
	protected int oat_file_end_;
	protected int patch_delta_;
	protected int image_roots_;
	protected int pointer_size_;
	protected int compile_pic_;

	protected long[] image_methods_ =
		new long[ImageMethod_Marshmallow.kImageMethodsCount.ordinal()];

	protected ArtImageSections sections;

	public ArtHeader_Marshmallow(BinaryReader reader) throws IOException {
		super(reader);
		parse(reader);
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
		patch_delta_ = reader.readNextInt();
		image_roots_ = reader.readNextInt();
		pointer_size_ = reader.readNextInt();
		compile_pic_ = reader.readNextInt();

		sections = new ImageSections_Marshmallow(reader, this);
		sections.parseSections(reader);

		for (int i = 0; i < image_methods_.length; ++i) {
			image_methods_[i] = reader.readNextLong();
		}

		sections.parse(reader);
	}

	@Override
	public int getImageBegin() {
		return image_begin_;
	}

	@Override
	public int getImageSize() {
		return image_size_;
	}

	@Override
	public int getPointerSize() {
		return pointer_size_;
	}

	/**
	 * Image methods.
	 */
	public long[] getImageMethods() {
		return image_methods_;
	}

	/**
	 * Checksum of the oat file we link to for load time sanity check.
	 */
	@Override
	public int getOatChecksum() {
		return oat_checksum_;
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

	@Override
	public void markup(Program program, TaskMonitor monitor) throws Exception {

		sections.markup(program, monitor);
	}

	@Override
	public int getArtMethodCountForVersion() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = (Structure) super.toDataType();

		String className = StructConverterUtil.parseName(ArtHeader_Marshmallow.class);
		try {
			structure.setName(className);
		}
		catch (InvalidNameException e) {
		}

		structure.add(DWORD, "image_begin_", null);
		structure.add(DWORD, "image_size_", null);
		structure.add(DWORD, "oat_checksum_", null);
		structure.add(DWORD, "oat_file_begin_", null);
		structure.add(DWORD, "oat_data_begin_", null);
		structure.add(DWORD, "oat_data_end_", null);
		structure.add(DWORD, "oat_file_end_", null);
		structure.add(DWORD, "patch_delta_", null);
		structure.add(DWORD, "image_roots_", null);
		structure.add(DWORD, "pointer_size_", null);
		structure.add(DWORD, "compile_pic_", null);

		for (int i = 0; i < sections.getSectionList().size(); ++i) {
			structure.add(sections.getSectionList().get(i).toDataType(), "section_" + i, null);
		}
		for (int i = 0; i < image_methods_.length; ++i) {
			structure.add(QWORD, "image_method_" + i, null);
		}
		return structure;
	}

}
