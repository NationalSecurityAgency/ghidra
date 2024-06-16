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
package ghidra.file.formats.android.vdex.headers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.ArrayUtils;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.file.formats.android.dex.DexHeaderFactory;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.file.formats.android.vdex.*;
import ghidra.file.formats.android.vdex.sections.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/android-s-beta-5/runtime/vdex_file.h#129">android-s-beta-5/runtime/vdex_file.h#129</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/android12-release/runtime/vdex_file.h#129">android12-release/runtime/vdex_file.h#129</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/android13-release/runtime/vdex_file.h#129">android13-release/runtime/vdex_file.h#129</a>
 */
public class VdexHeader_027 extends VdexHeader {

	private String vdex_version_;
	private int number_of_sections_;
	private List<VdexSectionHeader_S_T> sections = new ArrayList<>();
	private List<Integer> checksums = new ArrayList<>();

	public VdexHeader_027(BinaryReader reader)
			throws IOException, UnsupportedVdexVersionException {
		super(reader);
		vdex_version_ = reader.readNextAsciiString(4);
		number_of_sections_ = reader.readNextInt();
	}

	@Override
	public String getVersion() {
		return vdex_version_;
	}

	@Override
	public void parse(BinaryReader reader, TaskMonitor monitor)
			throws IOException, CancelledException {

		for (int i = 0; i < number_of_sections_; ++i) {
			monitor.checkCancelled();
			sections.add(new VdexSectionHeader_S_T(reader));
		}

		parseChecksums(reader, monitor);
		parseDexFiles(reader, monitor);
		parseVerifierDeps(reader, monitor);
		parseTypeLookupTable(reader, monitor);
	}

	private void parseChecksums(BinaryReader reader, TaskMonitor monitor)
			throws CancelledException, IOException {
		VdexSectionHeader_S_T checksumSection =
			sections.get(VdexSection_S_T.kChecksumSection.ordinal());
		if (checksumSection.getSectionSize() > 0) {
			reader.setPointerIndex(checksumSection.getSectionOffset());
			for (int i = 0; i < checksumSection.getSectionSize() / 4; ++i) {
				monitor.checkCancelled();
				checksums.add(reader.readNextInt());
			}
		}
	}

	private void parseDexFiles(BinaryReader reader, TaskMonitor monitor)
			throws CancelledException, IOException {
		VdexSectionHeader_S_T dexFileSection =
			sections.get(VdexSection_S_T.kDexFileSection.ordinal());
		if (dexFileSection.getSectionSize() > 0) {
			reader.setPointerIndex(dexFileSection.getSectionOffset());

			dexHeaderStartsList.add(Integer.toUnsignedLong(dexFileSection.getSectionOffset()));

			ByteProviderWrapper wrappedProvider = new ByteProviderWrapper(
				reader.getByteProvider(), dexFileSection.getSectionOffset(),
				dexFileSection.getSectionSize());

			BinaryReader wrappedReader =
				new BinaryReader(wrappedProvider, reader.isLittleEndian());

			DexHeader cdexHeader = DexHeaderFactory.getDexHeader(wrappedReader);
			dexHeaderList.add(cdexHeader);
		}
	}

	private void parseVerifierDeps(BinaryReader reader, TaskMonitor monitor)
			throws CancelledException, IOException {
		VdexSectionHeader_S_T verifierDepsSection =
			sections.get(VdexSection_S_T.kVerifierDepsSection.ordinal());
		if (verifierDepsSection.getSectionSize() > 0) {
			reader.setPointerIndex(verifierDepsSection.getSectionOffset());
			//TODO
		}
	}

	private void parseTypeLookupTable(BinaryReader reader, TaskMonitor monitor)
			throws CancelledException, IOException {
		VdexSectionHeader_S_T typeLookupTableSection =
			sections.get(VdexSection_S_T.kTypeLookupTableSection.ordinal());
		if (typeLookupTableSection.getSectionSize() > 0) {
			reader.setPointerIndex(typeLookupTableSection.getSectionOffset());
			//TODO
		}
	}

	@Override
	public int getVerifierDepsSize() {
		return 0;//not used in this VDEX version
	}

	@Override
	public int getQuickeningInfoSize() {
		return 0;//not used in this VDEX version
	}

	@Override
	public int[] getDexChecksums() {
		return ArrayUtils.toPrimitive(checksums.toArray(new Integer[checksums.size()]));
	}

	@Override
	public boolean isDexHeaderEmbeddedInDataType() {
		return true;
	}

	@Override
	public DexSectionHeader_002 getDexSectionHeader_002() {
		return null;//not used in this VDEX version
	}

	public String getVdexVersion() {
		return vdex_version_;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = (Structure) super.toDataType();

		structure.add(STRING, 4, "vdex_version_", null);
		structure.add(DWORD, "number_of_sections_", null);

		for (int i = 0; i < sections.size(); ++i) {
			structure.add(sections.get(i).toDataType(), "section_" + i, null);
		}

		for (int i = 0; i < checksums.size(); ++i) {
			structure.add(DWORD, "checksum_" + i, null);
		}

		toDataTypeDexFile(structure);
		toDataTypeVerifierDeps(structure);
		toDataTypeTypeLookupTable(structure);

		return structure;
	}

	private void toDataTypeDexFile(Structure structure) {
		VdexSectionHeader_S_T dexFileSection =
			sections.get(VdexSection_S_T.kDexFileSection.ordinal());
		if (dexFileSection.getSectionSize() > 0) {
			DataType array =
				new ArrayDataType(BYTE, dexFileSection.getSectionSize(), BYTE.getLength());
			structure.add(array, "cdex", null);
		}
	}

	private void toDataTypeVerifierDeps(Structure structure) {
		VdexSectionHeader_S_T verifierDepsSection =
			sections.get(VdexSection_S_T.kVerifierDepsSection.ordinal());
		if (verifierDepsSection.getSectionSize() > 0) {
			DataType array =
				new ArrayDataType(BYTE, verifierDepsSection.getSectionSize(), BYTE.getLength());
			structure.add(array, "verifier_deps", null);
		}
	}

	private void toDataTypeTypeLookupTable(Structure structure) {
		VdexSectionHeader_S_T typeLookupTableSection =
			sections.get(VdexSection_S_T.kTypeLookupTableSection.ordinal());
		if (typeLookupTableSection.getSectionSize() > 0) {
			DataType array =
				new ArrayDataType(BYTE, typeLookupTableSection.getSectionSize(), BYTE.getLength());
			structure.add(array, "type_lookup_table", null);
		}
	}
}
