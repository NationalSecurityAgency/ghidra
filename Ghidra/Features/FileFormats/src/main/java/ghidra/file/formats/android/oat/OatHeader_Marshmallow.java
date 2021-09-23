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
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 *  
 */
class OatHeader_Marshmallow extends OatHeader {

	protected int adler32_checksum_;
	protected int instruction_set_;
	protected int instruction_set_features_bitmap_;
	protected int dex_file_count_;
	protected int executable_offset_;
	protected int interpreter_to_interpreter_bridge_offset_;
	protected int interpreter_to_compiled_code_bridge_offset_;
	protected int jni_dlsym_lookup_offset_;
	protected int quick_generic_jni_trampoline_offset_;
	protected int quick_imt_conflict_trampoline_offset_;
	protected int quick_resolution_trampoline_offset_;
	protected int quick_to_interpreter_bridge_offset_;
	protected int image_patch_delta_;
	protected int image_file_location_oat_checksum_;
	protected int image_file_location_oat_data_begin_;
	protected int key_value_store_size_;

	protected List<String> orderedKeyList = new ArrayList<String>();//ordered as defined
	protected Map<String, String> key_value_store_ = new HashMap<String, String>();

	protected List<OatDexFile> oatDexFileList = new ArrayList<OatDexFile>();

	OatHeader_Marshmallow(BinaryReader reader) throws IOException {
		super(reader);

		adler32_checksum_ = reader.readNextInt();
		instruction_set_ = reader.readNextInt();
		instruction_set_features_bitmap_ = reader.readNextInt();
		dex_file_count_ = reader.readNextInt();
		executable_offset_ = reader.readNextInt();
		interpreter_to_interpreter_bridge_offset_ = reader.readNextInt();
		interpreter_to_compiled_code_bridge_offset_ = reader.readNextInt();
		jni_dlsym_lookup_offset_ = reader.readNextInt();
		quick_generic_jni_trampoline_offset_ = reader.readNextInt();
		quick_imt_conflict_trampoline_offset_ = reader.readNextInt();
		quick_resolution_trampoline_offset_ = reader.readNextInt();
		quick_to_interpreter_bridge_offset_ = reader.readNextInt();
		image_patch_delta_ = reader.readNextInt();
		image_file_location_oat_checksum_ = reader.readNextInt();
		image_file_location_oat_data_begin_ = reader.readNextInt();
		key_value_store_size_ = reader.readNextInt();
	}

	@Override
	public void parse(BinaryReader reader, Object additionalData)
			throws IOException, UnsupportedOatVersionException {
		int count = 0;
		while (count < key_value_store_size_) {
			String key = reader.readNextAsciiString();
			String value = reader.readNextAsciiString();
			count += key.length() + 1;
			count += value.length() + 1;
			key_value_store_.put(key, value);
			orderedKeyList.add(key);
		}

		for (int i = 0; i < dex_file_count_; ++i) {
			oatDexFileList
					.add(OatDexFileFactory.getOatDexFile(reader, getVersion(), additionalData));
		}
	}

	@Override
	public int getDexFileCount() {
		return dex_file_count_;
	}

	@Override
	public int getKeyValueStoreSize() {
		return key_value_store_size_;
	}

	@Override
	public List<OatDexFile> getOatDexFileList() {
		return Collections.unmodifiableList(oatDexFileList);
	}

	@Override
	public OatInstructionSet getInstructionSet() {
		return OatInstructionSet.valueOf(instruction_set_);
	}

	@Override
	public int getExecutableOffset() {
		return executable_offset_;
	}

	public int getInterpreterToInterpreterBridgeOffset() {
		return interpreter_to_interpreter_bridge_offset_;
	}

	public int getInstructionSetFeaturesBitmap() {
		return instruction_set_features_bitmap_;
	}

	public int getJniDlsymLookupOffset() {
		return jni_dlsym_lookup_offset_;
	}

	public int getQuickGenericJniTrampolineOffset() {
		return quick_generic_jni_trampoline_offset_;
	}

	public int getQuickImtConflictTrampolineOffset() {
		return quick_imt_conflict_trampoline_offset_;
	}

	public int getQuickResolutionTrampolineOffset() {
		return quick_resolution_trampoline_offset_;
	}

	public int getQuickToInterpreterBridgeOffset() {
		return quick_to_interpreter_bridge_offset_;
	}

	@Override
	public int getChecksum() {
		return adler32_checksum_;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String className = StructConverterUtil.parseName(OatHeader_Marshmallow.class);
		Structure structure = new StructureDataType(className, 0);
		structure.add(STRING, 4, "magic_", null);
		structure.add(STRING, 4, "version_", null);
		structure.add(DWORD, "adler32_checksum_", null);
		structure.add(DWORD, OatInstructionSet.DISPLAY_NAME, null);
		structure.add(DWORD, "instruction_set_features_bitmap_", null);
		structure.add(DWORD, "dex_file_count_", null);
		structure.add(DWORD, "executable_offset_", null);
		structure.add(DWORD, "interpreter_to_interpreter_bridge_offset_", null);
		structure.add(DWORD, "interpreter_to_compiled_code_bridge_offset_", null);
		structure.add(DWORD, "jni_dlsym_lookup_offset_", null);
		structure.add(DWORD, "quick_generic_jni_trampoline_offset_", null);
		structure.add(DWORD, "quick_imt_conflict_trampoline_offset_", null);
		structure.add(DWORD, "quick_resolution_trampoline_offset_", null);
		structure.add(DWORD, "quick_to_interpreter_bridge_offset_", null);
		structure.add(DWORD, "image_patch_delta_", null);
		structure.add(DWORD, "image_file_location_oat_checksum_", null);
		structure.add(DWORD, "image_file_location_oat_data_begin_", null);
		structure.add(DWORD, "key_value_store_size_", null);
		for (int i = 0; i < orderedKeyList.size(); ++i) {
			String key = orderedKeyList.get(i);
			String value = key_value_store_.get(key);
			structure.add(STRING, key.length() + 1, "key_value_store_[" + i + "].key", null);
			structure.add(STRING, value.length() + 1, "key_value_store_[" + i + "].value", null);
		}
		for (int i = 0; i < oatDexFileList.size(); ++i) {
			DataType dataType = oatDexFileList.get(i).toDataType();
			structure.add(dataType, dataType.getName(), null);
		}
		structure.setCategoryPath(new CategoryPath("/oat"));
		return structure;
	}
}
