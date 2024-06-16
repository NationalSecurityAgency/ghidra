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

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Validated DEX
 * 
 * VDEX files contain extracted DEX files. The VdexFile class maps the file to
 * memory and provides tools for accessing its individual sections.
 *
 * <a href="https://android.googlesource.com/platform/art/+/master/runtime/vdex_file.h">master/runtime/vdex_file.h</a>
 */
public final class VdexConstants {

	/**
	 * <pre>
	 * static constexpr uint8_t kVdexMagic[] = { 'v', 'd', 'e', 'x' };
	 * </pre>
	 */
	public final static String MAGIC = "vdex";

	/** 
	 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/o-preview/runtime/vdex_file.h#64">o-preview/runtime/vdex_file.h</a>
	 */
	public final static String vdex_version_003 = "003";
	/** 
	 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/oreo-release/runtime/vdex_file.h#69">oreo-release/runtime/vdex_file.h</a>
	 */
	public final static String VDEX_VERSION_006 = "006";
	/**
	 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/oreo-m2-release/runtime/vdex_file.h#76">oreo-m2-release/runtime/vdex_file.h</a>
	 * <br>
	 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/o-iot-preview-5/runtime/vdex_file.h#76">o-iot-preview-5/runtime/vdex_file.h</a>
	 */
	public final static String VDEX_VERSION_010 = "010";
	/** 
	 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/o-mr1-iot-preview-6/runtime/vdex_file.h#76">o-mr1-iot-preview-6/runtime/vdex_file.h</a>
	 */
	public final static String vdex_version_011 = "011";
	/**
	 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/pie-release/runtime/vdex_file.h#96">pie-release/runtime/vdex_file.h</a>
	 */
	public final static String VDEX_VERSION_019 = "019";
	/**
	 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/android10-release/runtime/vdex_file.h#118">android10-release/runtime/vdex_file.h</a>
	 * <br>
	 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/android11-release/runtime/vdex_file.h#118">android11-release/runtime/vdex_file</a>
	 */
	public final static String VDEX_VERSION_021 = "021";
	/**
	 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/android12-release/runtime/vdex_file.h#127">android12-release/runtime/vdex_file.h</a>
	 */
	public final static String VDEX_VERSION_027 = "027";

	/**
	 * The format version of the dex section header and the dex section, 
	 * containing both the dex code and the quickening data.
	 * Last update: Add owned section for CompactDex.
	 * Cite: https://android.googlesource.com/platform/art/+/refs/heads/pie-release/runtime/vdex_file.h
	 */
	public final static String kDexSectionVersion = "002";

	/**
	 * If the .vdex file has no dex section (hence no dex code nor quickening data),
	 * we encode this magic version.
	 * Cite: https://android.googlesource.com/platform/art/+/refs/heads/pie-release/runtime/vdex_file.h
	 */
	public final static String kDexSectionVersionEmpty = "000";

	/**
	 * Note: The file is called "primary" to match the naming with profiles.
	 */
	public final static String kVdexNameInDmFile = "primary.vdex";

	/**
	 * NOTE: only going to support RELEASE versions
	 */
	//@formatter:off
	public final static String[] SUPPORTED_VERSIONS = new String[] {
		VDEX_VERSION_006,
		VDEX_VERSION_010, 
		VDEX_VERSION_019, 
		VDEX_VERSION_021, 
		VDEX_VERSION_027,
	};
	//@formatter:on

	public final static boolean isSupportedVersion(String version) {
		for (String supportedVersion : SUPPORTED_VERSIONS) {
			if (supportedVersion.equals(version)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns true if the given program contain VDEX information.
	 * @param program the program to inspect for being VDEX
	 * @return true if the program is VDEX
	 */
	public final static boolean isVDEX(Program program) {
		if (program != null) {
			for (MemoryBlock block : program.getMemory().getBlocks()) {

				try (ByteProvider provider =
					MemoryByteProvider.createMemoryBlockByteProvider(program.getMemory(), block)) {
					String magic = new String(provider.readBytes(0, VdexConstants.MAGIC.length()));
					if (VdexConstants.MAGIC.equals(magic)) {
						return true;
					}
				}
				catch (Exception e) {
					//ignore
				}
			}
		}
		return false;
	}

	public final static Address findVDEX(Program program) {
		if (program != null) {
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				try (ByteProvider provider = MemoryByteProvider
						.createMemoryBlockByteProvider(program.getMemory(), block)) {
					String magic =
						new String(provider.readBytes(0, VdexConstants.MAGIC.length()));
					if (VdexConstants.MAGIC.equals(magic)) {
						return block.getStart();
					}
				}
				catch (Exception e) {
					//ignore
				}
			}
		}
		return null;
	}
}
