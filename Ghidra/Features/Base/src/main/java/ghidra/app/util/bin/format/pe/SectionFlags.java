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
package ghidra.app.util.bin.format.pe;

import java.util.HashSet;
import java.util.Set;

public enum SectionFlags {

	IMAGE_SCN_TYPE_NO_PAD("IMAGE_SCN_TYPE_NO_PAD", 0x00000008, "The section should not be padded to the next boundary."),
	IMAGE_SCN_RESERVED_0001("IMAGE_SCN_RESERVED_0001", 0x00000010, "Reserved for future use."),
	IMAGE_SCN_CNT_CODE("IMAGE_SCN_CNT_CODE", 0x00000020, "The section contains executable code."),
	IMAGE_SCN_CNT_INITIALIZED_DATA("IMAGE_SCN_CNT_INITIALIZED_DATA", 0x00000040, "The section contains initialized data."),
	IMAGE_SCN_CNT_UNINITIALIZED_DATA("IMAGE_SCN_CNT_UNINITIALIZED_DATA", 0x00000080, "The section contains uninitialized data."),
	IMAGE_SCN_LNK_OTHER("IMAGE_SCN_LNK_OTHER", 0x00000100, "Reserved for future use."),
	IMAGE_SCN_LNK_INFO("IMAGE_SCN_LNK_INFO", 0x00000200, "The section contains comments or other information.This is valid for object files only."),
	IMAGE_SCN_RESERVED_0040("IMAGE_SCN_RESERVED_0040", 0x00000400, "Reserved for future use."),
	IMAGE_SCN_LNK_REMOVE("IMAGE_SCN_LNK_REMOVE", 0x00000800, "The section will not become part of the image. This is valid only for object files."),
	IMAGE_SCN_LNK_COMDAT("IMAGE_SCN_LNK_COMDAT", 0x00001000, "The section contains COMDAT data. This is valid only for object files."),
	IMAGE_SCN_GPREL("IMAGE_SCN_GPREL", 0x00008000, "The section contains data referenced through the global pointer (GP)."),
	IMAGE_SCN_MEM_PURGEABLE("IMAGE_SCN_MEM_PURGEABLE", 0x00020000, "Reserved for future use."),
	IMAGE_SCN_MEM_16BIT("IMAGE_SCN_MEM_16BIT", 0x00020000, "Reserved for future use."),
	IMAGE_SCN_MEM_LOCKED("IMAGE_SCN_MEM_LOCKED", 0x00040000, "Reserved for future use."),
	IMAGE_SCN_MEM_PRELOAD("IMAGE_SCN_MEM_PRELOAD", 0x00080000, "Reserved for future use."),
	IMAGE_SCN_ALIGN_1BYTES("IMAGE_SCN_ALIGN_1BYTES", 0x00100000, "Align data on a 1-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_2BYTES("IMAGE_SCN_ALIGN_2BYTES", 0x00200000, "Align data on a 2-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_4BYTES("IMAGE_SCN_ALIGN_4BYTES", 0x00300000, "Align data on a 4-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_8BYTES("IMAGE_SCN_ALIGN_8BYTES", 0x00400000, "Align data on an 8-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_16BYTES("IMAGE_SCN_ALIGN_16BYTES", 0x00500000, "Align data on a 16-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_32BYTES("IMAGE_SCN_ALIGN_32BYTES", 0x00600000, "Align data on a 32-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_64BYTES("IMAGE_SCN_ALIGN_64BYTES", 0x00700000, "Align data on a 64-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_128BYTES("IMAGE_SCN_ALIGN_128BYTES", 0x00800000, "Align data on a 128-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_256BYTES("IMAGE_SCN_ALIGN_256BYTES", 0x00900000, "Align data on a 256-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_512BYTES("IMAGE_SCN_ALIGN_512BYTES", 0x00A00000, "Align data on a 512-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_1024BYTES("IMAGE_SCN_ALIGN_1024BYTES", 0x00B00000, "Align data on a 1024-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_2048BYTES("IMAGE_SCN_ALIGN_2048BYTES", 0x00C00000, "Align data on a 2048-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_4096BYTES("IMAGE_SCN_ALIGN_4096BYTES", 0x00D00000, "Align data on a 4096-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_8192BYTES("IMAGE_SCN_ALIGN_8192BYTES", 0x00E00000, "Align data on an 8192-byte boundary. Valid only for object files."),
	IMAGE_SCN_LNK_NRELOC_OVFL("IMAGE_SCN_LNK_NRELOC_OVFL", 0x01000000, "The section contains extended relocations."),
	IMAGE_SCN_MEM_DISCARDABLE("IMAGE_SCN_MEM_DISCARDABLE", 0x02000000, "The section can be discarded as needed."),
	IMAGE_SCN_MEM_NOT_CACHED("IMAGE_SCN_MEM_NOT_CACHED", 0x04000000, "The section cannot be cached."),
	IMAGE_SCN_MEM_NOT_PAGED("IMAGE_SCN_MEM_NOT_PAGED", 0x08000000, "The section is not pageable."),
	IMAGE_SCN_MEM_SHARED("IMAGE_SCN_MEM_SHARED", 0x10000000, "The section can be shared in memory."),
	IMAGE_SCN_MEM_EXECUTE("IMAGE_SCN_MEM_EXECUTE", 0x20000000, "The section can be executed as code."),
	IMAGE_SCN_MEM_READ("IMAGE_SCN_MEM_READ", 0x40000000, "The section can be read."),
	IMAGE_SCN_MEM_WRITE("IMAGE_SCN_MEM_WRITE", 0x80000000, "The section can be written to.");

	private final String alias;
	private final int mask;
	private final String description;

	private SectionFlags(String alias, int mask, String description) {
		this.alias = alias;
		this.mask = mask;
		this.description = description;
	}

	public String getAlias() {
		return alias;
	}

	public int getMask() {
		return mask;
	}

	public String getDescription() {
		return description;
	}

	public static Set<SectionFlags> resolveFlags(int value) {
		Set<SectionFlags> applied = new HashSet<>();
		for (SectionFlags ch : values()) {
			if ((ch.getMask() & value) == ch.getMask()) {
				applied.add(ch);
			}
		}
		return applied;
	}
}
