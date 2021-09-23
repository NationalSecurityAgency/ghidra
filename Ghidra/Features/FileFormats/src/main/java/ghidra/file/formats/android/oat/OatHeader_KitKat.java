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
package ghidra.file.formats.android.oat;

import java.io.IOException;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class OatHeader_KitKat extends OatHeader {

	protected int adler32_checksum_;
	protected int instruction_set_;
	protected int dex_file_count_;
	protected int executable_offset_;
	protected int interpreter_to_interpreter_bridge_offset_;
	protected int interpreter_to_compiled_code_bridge_offset_;
	protected int jni_dlsym_lookup_offset_;
	protected int portable_resolution_trampoline_offset_;
	protected int portable_to_interpreter_bridge_offset_;
	protected int image_file_location_oat_checksum_;
	protected int image_file_location_oat_data_begin_;
	protected int image_file_location_size_;
	protected byte[] image_file_location_data_;  // note variable width data at end

	OatHeader_KitKat(BinaryReader reader) throws IOException {
		super(reader);
		adler32_checksum_ = reader.readNextInt();
		instruction_set_ = reader.readNextInt();
		dex_file_count_ = reader.readNextInt();
		executable_offset_ = reader.readNextInt();
		interpreter_to_interpreter_bridge_offset_ = reader.readNextInt();
		interpreter_to_compiled_code_bridge_offset_ = reader.readNextInt();
		jni_dlsym_lookup_offset_ = reader.readNextInt();
		portable_resolution_trampoline_offset_ = reader.readNextInt();
		portable_to_interpreter_bridge_offset_ = reader.readNextInt();
		image_file_location_oat_checksum_ = reader.readNextInt();
		image_file_location_oat_data_begin_ = reader.readNextInt();
		image_file_location_size_ = reader.readNextInt();
	}

	@Override
	public void parse(BinaryReader reader, Object additionalData) throws IOException {
		//do nothing
	}

	public int getChecksum() {
		return adler32_checksum_;
	}

	@Override
	public OatInstructionSet getInstructionSet() {
		return OatInstructionSet.valueOf(instruction_set_);
	}

	@Override
	public int getDexFileCount() {
		return dex_file_count_;
	}

	@Override
	public int getExecutableOffset() {
		return executable_offset_;
	}

	public int getInterpreterToInterpreterBridgeOffset() {
		return interpreter_to_interpreter_bridge_offset_;
	}

	public int getInterpreterToCompiledCodeBridgeOffset() {
		return interpreter_to_compiled_code_bridge_offset_;
	}

	public int getJniDlsymLookupOffset() {
		return jni_dlsym_lookup_offset_;
	}

	public int getPortableResolutionTrampolineOffset() {
		return portable_resolution_trampoline_offset_;
	}

	public int getPortableToInterpreterBridgeOffset() {
		return portable_to_interpreter_bridge_offset_;
	}

	public int getImageFileLocationOatChecksum() {
		return image_file_location_oat_checksum_;
	}

	public int getImageFileLocationOatDataBegin() {
		return image_file_location_oat_data_begin_;
	}

	public int getImageFileLocationSize_() {
		return image_file_location_size_;
	}

	public byte[] getImageFileLocationData_() {
		return image_file_location_data_;
	}

	@Override
	public int getKeyValueStoreSize() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public List<OatDexFile> getOatDexFileList() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String className = StructConverterUtil.parseName(OatHeader_KitKat.class);
		Structure structure = new StructureDataType(className, 0);
		structure.add(STRING, 4, "magic_", null);
		structure.add(STRING, 4, "version_", null);
		structure.add(DWORD, "adler32_checksum_", null);
		structure.add(DWORD, OatInstructionSet.DISPLAY_NAME, null);
		structure.add(DWORD, "dex_file_count_", null);
		structure.add(DWORD, "executable_offset_", null);
		structure.add(DWORD, "interpreter_to_interpreter_bridge_offset_", null);
		structure.add(DWORD, "interpreter_to_compiled_code_bridge_offset_", null);
		structure.add(DWORD, "jni_dlsym_lookup_offset_", null);
		structure.add(DWORD, "portable_resolution_trampoline_offset_", null);
		structure.add(DWORD, "portable_to_interpreter_bridge_offset_", null);
		structure.add(DWORD, "image_file_location_oat_checksum_", null);
		structure.add(DWORD, "image_file_location_oat_data_begin_", null);
		structure.add(DWORD, "image_file_location_size_", null);
		structure.setCategoryPath(new CategoryPath("/oat"));
		return structure;
	}
}
