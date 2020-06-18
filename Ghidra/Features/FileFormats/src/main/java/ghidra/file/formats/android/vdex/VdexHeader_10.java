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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.file.formats.android.dex.DexHeaderFactory;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.program.model.data.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * https://android.googlesource.com/platform/art/+/refs/heads/android10-release/runtime/vdex_file.h
 */
public class VdexHeader_10 extends VdexHeader {

	private String dex_section_version_;
	private int number_of_dex_files_;
	private int verifier_deps_size_;
	private int bootclasspath_checksums_size_;
	private int class_loader_context_size_;
	private int[] dex_checksums_;
	private DexSectionHeader_002 sectionHeader;
	private List<Integer> quickenTableOffsetList = new ArrayList<>();

	public VdexHeader_10(BinaryReader reader) throws IOException, UnsupportedVdexVersionException {
		super(reader);
		verifier_deps_version_ = reader.readNextAsciiString(4);
		dex_section_version_ = reader.readNextAsciiString(4);
		number_of_dex_files_ = reader.readNextInt();
		verifier_deps_size_ = reader.readNextInt();
		bootclasspath_checksums_size_ = reader.readNextInt();
		class_loader_context_size_ = reader.readNextInt();

		// dex checksums appear as contiguous list

		dex_checksums_ = new int[number_of_dex_files_];
		for (int i = 0; i < number_of_dex_files_; ++i) {
			dex_checksums_[i] = reader.readNextInt();
		}

		if (VdexConstants.kDexSectionVersion.equals(dex_section_version_)) {
			sectionHeader = new DexSectionHeader_002(reader);

			for (int i = 0; i < number_of_dex_files_; ++i) {
				quickenTableOffsetList.add(reader.readNextInt());

				long index = reader.getPointerIndex();

				dexHeaderStartsList.add(index);

				ByteProviderWrapper wrapperProvider = new ByteProviderWrapper(
					reader.getByteProvider(), index, reader.getByteProvider().length() - index);
				BinaryReader wrappedReader =
					new BinaryReader(wrapperProvider, reader.isLittleEndian());

				DexHeader cdexHeader = DexHeaderFactory.getDexHeader(wrappedReader);
				dexHeaderList.add(cdexHeader);

				reader.setPointerIndex(index + cdexHeader.getFileSize());
			}
		}
		else if (VdexConstants.kDexSectionVersionEmpty.equals(dex_section_version_)) {
			stringTable = new VdexStringTable( reader );
		}
		else {
			throw new UnsupportedVdexVersionException(
				"Unknown VDEX section version: " + dex_section_version_);
		}
	}

	public void parse(BinaryReader reader, TaskMonitor monitor)
			throws IOException, CancelledException {
		//do nothing
	}

	public String getDexSectionVersion() {
		return dex_section_version_;
	}

	public int getNumberOfDexFiles() {
		return number_of_dex_files_;
	}

	@Override
	public int getVerifierDepsSize() {
		return verifier_deps_size_;
	}

	@Override
	public int getQuickeningInfoSize() {
		// unsupported...
		return 0;
	}

	@Override
	public DexSectionHeader_002 getDexSectionHeader_002() {
		return sectionHeader;
	}

	public int getBootclasspathChecksumsSize() {
		return bootclasspath_checksums_size_;
	}

	public int getClassLoaderContextSize() {
		return class_loader_context_size_;
	}

	@Override
	public int[] getDexChecksums() {
		return dex_checksums_;
	}

	@Override
	public boolean isDexHeaderEmbeddedInDataType() {
		return false;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String className = StructConverterUtil.parseName(VdexHeader_10.class);
		Structure structure = new StructureDataType(className + "_" + number_of_dex_files_, 0);
		structure.add(STRING, 4, "magic_", null);
		structure.add(STRING, 4, "verifier_deps_version_", null);
		structure.add(STRING, 4, "dex_section_version_", null);
		structure.add(DWORD, "number_of_dex_files_", null);
		structure.add(DWORD, "verifier_deps_size_", null);
		structure.add(DWORD, "bootclasspath_checksums_size_", null);
		structure.add(DWORD, "class_loader_context_size_", null);
		for (int i = 0; i < dex_checksums_.length; ++i) {
			structure.add(DWORD, "dex_checksum_" + i, null);
		}
		if (sectionHeader != null) {
			structure.add(sectionHeader.toDataType(), "dex_section_header_", null);
		}
		if (stringTable != null && stringTable.getStringCount() > 0) {
			structure.add(stringTable.toDataType(), "strings", null);
		}
		structure.setCategoryPath(new CategoryPath("/vdex"));
		return structure;
	}

}
