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
 * https://android.googlesource.com/platform/art/+/refs/heads/android10-release/runtime/art_method.h
 * 
 *
 */
public class ArtMethod implements StructConverter {
	private final int pointerSize;
	private final String artVersion;

	private int declaring_class_;
	private int access_flags_;
	private int dex_code_item_offset_;
	private int dex_method_index_;
	private short method_index_;
	private short hotness_count_;
	private short imt_index_;
	private short padding_;

	private long dex_cache_resolved_methods_;
	private long dex_cache_resolved_types_;
	private long entry_point_from_interpreter_;
	private long entry_point_from_jni_;
	private long data_;
	private long unknown1_;
	private long entry_point_from_quick_compiled_code_;
	private int unknown2_;

	public ArtMethod(BinaryReader reader, int pointerSize, String artVersion) throws IOException {
		this.pointerSize = pointerSize;
		this.artVersion = artVersion;

		if (ArtConstants.VERSION_MARSHMALLOW_RELEASE.equals(artVersion)) {
			if (pointerSize == 4) {
				declaring_class_ = reader.readNextInt();
				dex_cache_resolved_methods_ = Integer.toUnsignedLong(reader.readNextInt());
				dex_cache_resolved_types_ = Integer.toUnsignedLong(reader.readNextInt());
				access_flags_ = reader.readNextInt();
				dex_code_item_offset_ = reader.readNextInt();
				dex_method_index_ = reader.readNextInt();
				method_index_ = reader.readNextShort();
				padding_ = reader.readNextShort();
				entry_point_from_interpreter_ = Integer.toUnsignedLong(reader.readNextInt());
				entry_point_from_jni_ = Integer.toUnsignedLong(reader.readNextInt());
				entry_point_from_quick_compiled_code_ =
					Integer.toUnsignedLong(reader.readNextInt());
			}
			else if (pointerSize == 8) {
				throw new IOException("Unsupported 64-bit ART method format: " + artVersion);
			}
		}
		else if (ArtConstants.VERSION_NOUGAT_RELEASE.equals(artVersion) ||
			ArtConstants.VERSION_NOUGAT_MR2_PIXEL_RELEASE.equals(artVersion)) {

			if (pointerSize == 4) {
				declaring_class_ = reader.readNextInt();
				access_flags_ = reader.readNextInt();
				dex_code_item_offset_ = reader.readNextInt();
				dex_method_index_ = reader.readNextInt();
				method_index_ = reader.readNextShort();
				hotness_count_ = reader.readNextShort();
				dex_cache_resolved_methods_ = Integer.toUnsignedLong(reader.readNextInt());
				dex_cache_resolved_types_ = Integer.toUnsignedLong(reader.readNextInt());
				entry_point_from_jni_ = Integer.toUnsignedLong(reader.readNextInt());
				entry_point_from_quick_compiled_code_ =
					Integer.toUnsignedLong(reader.readNextInt());
			}
			else if (pointerSize == 8) {
				declaring_class_ = reader.readNextInt();
				access_flags_ = reader.readNextInt();
				dex_code_item_offset_ = reader.readNextInt();
				dex_method_index_ = reader.readNextInt();
				method_index_ = reader.readNextShort();
				hotness_count_ = reader.readNextShort();
				imt_index_ = reader.readNextShort();
				padding_ = reader.readNextShort();
				dex_cache_resolved_methods_ = reader.readNextLong();
				dex_cache_resolved_types_ = reader.readNextLong();
				entry_point_from_jni_ = reader.readNextLong();
				entry_point_from_quick_compiled_code_ = reader.readNextLong();
			}
		}
		else if (ArtConstants.VERSION_OREO_RELEASE.equals(artVersion) ||
			ArtConstants.VERSION_OREO_DR1_RELEASE.equals(artVersion) ||
			ArtConstants.VERSION_OREO_MR1_RELEASE.equals(artVersion)) {

			if (pointerSize == 4) {
				declaring_class_ = reader.readNextInt();
				access_flags_ = reader.readNextInt();
				dex_code_item_offset_ = reader.readNextInt();
				dex_method_index_ = reader.readNextInt();
				method_index_ = reader.readNextShort();
				hotness_count_ = reader.readNextShort();
				data_ = reader.readNextLong();
				entry_point_from_quick_compiled_code_ =
					Integer.toUnsignedLong(reader.readNextInt());
			}
			else if (pointerSize == 8) {
				declaring_class_ = reader.readNextInt();
				access_flags_ = reader.readNextInt();
				dex_code_item_offset_ = reader.readNextInt();
				dex_method_index_ = reader.readNextInt();
				method_index_ = reader.readNextShort();
				hotness_count_ = reader.readNextShort();
				imt_index_ = reader.readNextShort();
				padding_ = reader.readNextShort();
				data_ = reader.readNextLong();
				unknown1_ = reader.readNextLong();
				entry_point_from_quick_compiled_code_ = reader.readNextLong();
			}
		}
		else if (ArtConstants.VERSION_PIE_RELEASE.equals(artVersion)) {
			declaring_class_ = reader.readNextInt();
			access_flags_ = reader.readNextInt();
			dex_code_item_offset_ = reader.readNextInt();
			dex_method_index_ = reader.readNextInt();
			method_index_ = reader.readNextShort();
			hotness_count_ = reader.readNextShort();
			imt_index_ = reader.readNextShort();
			padding_ = reader.readNextShort();

			if (pointerSize == 4) {
				data_ = Integer.toUnsignedLong(reader.readNextInt());
			}
			else if (pointerSize == 8) {
				data_ = reader.readNextLong();
				entry_point_from_quick_compiled_code_ = reader.readNextLong();
			}
		}
		else if (ArtConstants.VERSION_10_RELEASE.equals(artVersion)) {
			declaring_class_ = reader.readNextInt();
			access_flags_ = reader.readNextInt();
			dex_code_item_offset_ = reader.readNextInt();
			dex_method_index_ = reader.readNextInt();
			method_index_ = reader.readNextShort();
			hotness_count_ = reader.readNextShort();
			imt_index_ = reader.readNextShort();
			padding_ = reader.readNextShort();

			if (pointerSize == 4) {
				data_ = Integer.toUnsignedLong(reader.readNextInt());
			}
			else if (pointerSize == 8) {
				data_ = reader.readNextLong();
				entry_point_from_quick_compiled_code_ = reader.readNextLong();
			}
		}
		else if (ArtConstants.VERSION_11_RELEASE.equals(artVersion)) {
			declaring_class_ = reader.readNextInt();
			access_flags_ = reader.readNextInt();
			dex_code_item_offset_ = reader.readNextInt();
			dex_method_index_ = reader.readNextInt();
			method_index_ = reader.readNextShort();
			hotness_count_ = reader.readNextShort();
			imt_index_ = reader.readNextShort();
			padding_ = reader.readNextShort();

			if (pointerSize == 4) {
				data_ = Integer.toUnsignedLong(reader.readNextInt());
			}
			else if (pointerSize == 8) {
				data_ = reader.readNextLong();
				entry_point_from_quick_compiled_code_ = reader.readNextLong();
			}
		}
		else {
			throw new IOException("Unsupported ART method format: " + artVersion);
		}
	}

	public int getDeclaringClass() {
		return declaring_class_;
	}

	public int getAccessFlags() {
		return access_flags_;
	}

	public int getDexCodeItemOffset() {
		return dex_code_item_offset_;
	}

	public int getDexMethodIndex() {
		return dex_method_index_;
	}

	public short getMethodIndex() {
		return method_index_;
	}

	public short getHotnessCount() {
		return hotness_count_;
	}

	public short getImtIndex() {
		return imt_index_;
	}

	public short getPadding() {
		return padding_;
	}

	public long getData() {
		return data_;
	}

	public long getEntryPointFromInterpreter() {
		return entry_point_from_interpreter_;
	}

	public long getEntryPointFromQuickCompiledCode() {
		return entry_point_from_quick_compiled_code_;
	}

	public long getDexCacheResolvedMethods() {
		return dex_cache_resolved_methods_;
	}

	public long getDexCacheResolvedTypes() {
		return dex_cache_resolved_types_;
	}

	public long getEntryPointFromJNI() {
		return entry_point_from_jni_;
	}

	public long getUnknown1() {
		return unknown1_;
	}

	public int getUnknown2() {
		return unknown2_;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		DataType ptr32 = new Pointer32DataType();
		DataType ptr64 = new Pointer64DataType();

		String name = StructConverterUtil.parseName(ArtMethod.class);
		Structure struct = new StructureDataType(name, 0);
		struct.setCategoryPath(new CategoryPath("/art"));

		if (ArtConstants.VERSION_MARSHMALLOW_RELEASE.equals(artVersion)) {
			if (pointerSize == 4) {
				struct.add(DWORD, "declaring_class_", null);
				struct.add(DWORD, "dex_cache_resolved_methods_", null);
				struct.add(DWORD, "dex_cache_resolved_types_", null);
				struct.add(DWORD, "access_flags_", null);
				struct.add(DWORD, "dex_code_item_offset_", null);
				struct.add(DWORD, "dex_method_index_", null);
				struct.add(WORD, "method_index_", null);
				struct.add(WORD, "padding_", null);
				struct.add(DWORD, "entry_point_from_interpreter_", null);
				struct.add(DWORD, "entry_point_from_jni_", null);
				struct.add(DWORD, "entry_point_from_quick_compiled_code_", null);
			}
			else if (pointerSize == 8) {
				throw new IOException("Unsupported 64-bit ART method format: " + artVersion);
			}
		}
		else if (ArtConstants.VERSION_NOUGAT_RELEASE.equals(artVersion) ||
			ArtConstants.VERSION_NOUGAT_MR2_PIXEL_RELEASE.equals(artVersion)) {

			if (pointerSize == 4) {
				struct.add(ptr32, "declaring_class_", null);
				struct.add(DWORD, "access_flags_", null);
				struct.add(DWORD, "dex_code_item_offset_", null);
				struct.add(DWORD, "dex_method_index_", null);
				struct.add(WORD, "method_index_", null);
				struct.add(WORD, "hotness_count_", null);
				struct.add(DWORD, "dex_cache_resolved_methods_", null);
				struct.add(DWORD, "dex_cache_resolved_types_", null);
				struct.add(ptr32, "entry_point_from_jni_", null);
				struct.add(ptr32, "entry_point_from_quick_compiled_code_", null);
			}
			else if (pointerSize == 8) {
				struct.add(ptr32, "declaring_class_", null);
				struct.add(DWORD, "access_flags_", null);
				struct.add(DWORD, "dex_code_item_offset_", null);
				struct.add(DWORD, "dex_method_index_", null);
				struct.add(WORD, "method_index_", null);
				struct.add(WORD, "hotness_count_", null);
				struct.add(WORD, "imt_index_", null);
				struct.add(WORD, "padding", null);
				struct.add(QWORD, "dex_cache_resolved_methods_", null);
				struct.add(QWORD, "dex_cache_resolved_types_", null);
				struct.add(ptr64, "entry_point_from_jni_", null);
				struct.add(ptr64, "entry_point_from_quick_compiled_code_", null);
			}
		}
		else if (ArtConstants.VERSION_OREO_RELEASE.equals(artVersion) ||
			ArtConstants.VERSION_OREO_DR1_RELEASE.equals(artVersion) ||
			ArtConstants.VERSION_OREO_MR1_RELEASE.equals(artVersion)) {

			if (pointerSize == 4) {
				struct.add(ptr32, "declaring_class_", null);
				struct.add(DWORD, "access_flags_", null);
				struct.add(DWORD, "dex_code_item_offset_", null);
				struct.add(DWORD, "dex_method_index_", null);
				struct.add(WORD, "method_index_", null);
				struct.add(WORD, "hotness_count_", null);
				struct.add(QWORD, "data", null);
				struct.add(ptr32, "entry_point_from_quick_compiled_code_", null);
			}
			else if (pointerSize == 8) {
				struct.add(ptr32, "declaring_class_", null);
				struct.add(DWORD, "access_flags_", null);
				struct.add(DWORD, "dex_code_item_offset_", null);
				struct.add(DWORD, "dex_method_index_", null);
				struct.add(WORD, "method_index_", null);
				struct.add(WORD, "hotness_count_", null);
				struct.add(WORD, "imt_index_", null);
				struct.add(WORD, "padding", null);
				struct.add(QWORD, "data", null);
				struct.add(QWORD, "unknown1_", null);
				struct.add(ptr64, "entry_point_from_quick_compiled_code_", null);
			}
		}
		else if (ArtConstants.VERSION_PIE_RELEASE.equals(artVersion)) {
			struct.add(ptr32, "declaring_class_", null);
			struct.add(DWORD, "access_flags_", null);
			struct.add(DWORD, "dex_code_item_offset_", null);
			struct.add(DWORD, "dex_method_index_", null);
			struct.add(WORD, "method_index_", null);
			struct.add(WORD, "hotness_count_", null);
			struct.add(WORD, "imt_index_", null);
			struct.add(WORD, "padding", null);

			if (pointerSize == 4) {
				struct.add(DWORD, "data", null);
			}
			else if (pointerSize == 8) {
				struct.add(QWORD, "data", null);
				struct.add(QWORD, "entry_point_from_quick_compiled_code_", null);
			}
		}
		else if (ArtConstants.VERSION_10_RELEASE.equals(artVersion)) {
			struct.add(ptr32, "declaring_class_", null);
			struct.add(DWORD, "access_flags_", null);
			struct.add(DWORD, "dex_code_item_offset_", null);
			struct.add(DWORD, "dex_method_index_", null);
			struct.add(WORD, "method_index_", null);
			struct.add(WORD, "hotness_count_", null);
			struct.add(WORD, "imt_index_", null);
			struct.add(WORD, "padding", null);

			if (pointerSize == 4) {
				struct.add(DWORD, "data", null);
			}
			else if (pointerSize == 8) {
				struct.add(QWORD, "data", null);
				struct.add(ptr64, "entry_point_from_quick_compiled_code_", null);
			}
		}
		else if (ArtConstants.VERSION_11_RELEASE.equals(artVersion)) {
			struct.add(ptr32, "declaring_class_", null);
			struct.add(DWORD, "access_flags_", null);
			struct.add(DWORD, "dex_code_item_offset_", null);
			struct.add(DWORD, "dex_method_index_", null);
			struct.add(WORD, "method_index_", null);
			struct.add(WORD, "hotness_count_", null);
			struct.add(WORD, "imt_index_", null);
			struct.add(WORD, "padding", null);

			if (pointerSize == 4) {
				struct.add(DWORD, "data", null);
			}
			else if (pointerSize == 8) {
				struct.add(QWORD, "data", null);
				struct.add(QWORD, "entry_point_from_quick_compiled_code_", null);
			}
		}
		else {
			throw new IOException("Unsupported ART method format: " + artVersion);
		}
		return struct;
	}

}
