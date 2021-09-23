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
 * https://android.googlesource.com/platform/art/+/master/runtime/vdex_file.h
 */
public final class VdexConstants {

	/**
	 * <pre>
	 * static constexpr uint8_t kVdexMagic[] = { 'v', 'd', 'e', 'x' };
	 * </pre>
	 */
	public final static String MAGIC = "vdex";

	public final static String version_o_preview = "003";
	public final static String VERSION_OREO_RELEASE = "006";
	public final static String VERSION_OREO_M2_RELEASE = "010";
	public final static String version_o_iot_preview_5 = "010";
	public final static String version_o_mr1_iot_preview_6 = "011";
	public final static String VERSION_PIE_RELEASE = "019";
	public final static String VERSION_10_RELEASE = "021";
	public final static String VERSION_11_RELEASE = "021";

	public final static String version_master = "021";

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
	public final static String[] SUPPORTED_VERSIONS = new String[] { VERSION_OREO_RELEASE,
		VERSION_OREO_M2_RELEASE, VERSION_PIE_RELEASE, VERSION_10_RELEASE, VERSION_11_RELEASE, };

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
					new MemoryByteProvider(program.getMemory(), block.getStart())) {
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
		try {
			if (program != null) {
				for (MemoryBlock block : program.getMemory().getBlocks()) {
					ByteProvider provider =
						new MemoryByteProvider(program.getMemory(), block.getStart());
					try {
						String magic =
							new String(provider.readBytes(0, VdexConstants.MAGIC.length()));
						if (VdexConstants.MAGIC.equals(magic)) {
							return block.getStart();
						}
					}
					catch (Exception e) {
						//ignore
					}
					finally {
						provider.close();
					}
				}
			}
		}
		catch (IOException e) {
			//ignore
		}
		return null;
	}
}
