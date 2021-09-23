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
import ghidra.file.formats.android.dex.DexHeaderFactory;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.file.formats.android.dex.format.DexHeaderQuickMethods;
import ghidra.program.model.data.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * https://android.googlesource.com/platform/art/+/refs/heads/oreo-release/runtime/vdex_file.h
 * https://android.googlesource.com/platform/art/+/refs/heads/oreo-m2-release/runtime/vdex_file.h
 */
public class VdexHeader_Oreo extends VdexHeader {

	private String version_;
	private int number_of_dex_files_;
	private int dex_size_;
	private int verifier_deps_size_;
	private int quickening_info_size_;
	private int[] dex_checksums_;

	public VdexHeader_Oreo(BinaryReader reader) throws IOException {
		super(reader);
		version_ = reader.readNextAsciiString(4);
		number_of_dex_files_ = reader.readNextInt();
		dex_size_ = reader.readNextInt();
		verifier_deps_size_ = reader.readNextInt();
		quickening_info_size_ = reader.readNextInt();
		dex_checksums_ = reader.readNextIntArray(number_of_dex_files_);
	}

	public void parse(BinaryReader reader, TaskMonitor monitor)
			throws IOException, CancelledException {
		monitor.setMessage("Parsing DEX files inside VDEX (oreo)...");
		monitor.setProgress(0);
		monitor.setMaximum(number_of_dex_files_ * 2);
		for (int i = 0; i < number_of_dex_files_; ++i) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			long index = reader.getPointerIndex();
			ByteProvider provider = reader.getByteProvider();
			ByteProvider tmpProvider =
				new ByteProviderWrapper(provider, index, provider.length() - index);
			BinaryReader tmpReader = new BinaryReader(tmpProvider, reader.isLittleEndian());
			tmpReader.setPointerIndex(0);
			dexHeaderList.add(DexHeaderFactory.getDexHeader(tmpReader));
			tmpReader.setPointerIndex(0);
			int length = DexHeaderQuickMethods.getDexLength(tmpReader);
			dexHeaderStartsList.add(index);
			reader.setPointerIndex(index + length);
		}
		//stringTable = new VdexStringTable( reader );
	}

	public String getVersion() {
		return version_;
	}

	public int getNumberOfDexFiles() {
		return number_of_dex_files_;
	}

	public int getDexSize() {
		return dex_size_;
	}

	@Override
	public int getVerifierDepsSize() {
		return verifier_deps_size_;
	}

	@Override
	public int getQuickeningInfoSize() {
		return quickening_info_size_;
	}

	@Override
	public int[] getDexChecksums() {
		return dex_checksums_;
	}

	@Override
	public boolean isDexHeaderEmbeddedInDataType() {
		return true;
	}

	@Override
	public DexSectionHeader_002 getDexSectionHeader_002() {
		return null;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String className = StructConverterUtil.parseName(VdexHeader_Oreo.class);
		Structure structure = new StructureDataType(className + "_" + number_of_dex_files_, 0);
		structure.add(STRING, 4, "magic_", null);
		structure.add(STRING, 4, "version_", null);
		structure.add(DWORD, "number_of_dex_files_", null);
		structure.add(DWORD, "dex_size_", null);
		structure.add(DWORD, "verifier_deps_size_", null);
		structure.add(DWORD, "quickening_info_size_", null);
		for (int i = 0; i < dex_checksums_.length; ++i) {
			structure.add(DWORD, "dex_checksums_" + i, null);
		}
		for (int i = 0; i < dexHeaderList.size(); ++i) {
			DexHeader dexHeader = dexHeaderList.get(i);
			DataType dexHeaderDataType = dexHeader.toDataType();
			try {
				dexHeaderDataType.setName(dexHeaderDataType.getName() + "_" + i);
			}
			catch (Exception e) {
				//ignore...
			}
			structure.add(dexHeaderDataType, "dex_header_" + i, null);
			ArrayDataType array = new ArrayDataType(BYTE,
				dexHeader.getFileSize() - dexHeaderDataType.getLength(), BYTE.getLength());
			structure.add(array, "dex_header_bytes_" + i, null);
		}
		if (stringTable != null) {
			structure.add(stringTable.toDataType(), "strings", null);
		}
		structure.setCategoryPath(new CategoryPath("/vdex"));
		return structure;
	}

}
