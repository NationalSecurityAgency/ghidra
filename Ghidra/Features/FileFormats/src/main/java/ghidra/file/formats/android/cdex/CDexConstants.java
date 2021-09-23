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
package ghidra.file.formats.android.cdex;

import ghidra.program.model.listing.Program;

/**
 * Android .CDEX files.
 * 
 * CompactDex is a currently ART internal dex file format that aims to reduce
 * storage/RAM usage.
 * 
 * https://android.googlesource.com/platform/art/+/master/runtime/dex/compact_dex_file.h
 * 
 * https://android.googlesource.com/platform/art/+/master/libdexfile/dex/compact_dex_file.h
 */
public final class CDexConstants {

	public final static String NAME = "Compact Dalvik Executable (CDEX)";

	/**
	 * <pre>
	 * static constexpr uint8_t kDexMagic[kDexMagicSize] = { 'c', 'd', 'e', 'x' };
	 * </pre>
	 */
	public final static String MAGIC = "cdex";

	/**
	 * <pre>
	 * static constexpr uint8_t kDexMagicVersion[] = {'0', '0', '1', '\0'};
	 * </pre>
	 */
	public final static String VERSION_001 = "001";

	/**
	 * <pre>
	 * static constexpr uint8_t kDexMagicVersion[] = {'0', '0', '2', '\0'};
	 * </pre>
	 */
	public final static String VERSION_002 = "002";

	/**
	 * Returns true if the given program contain CDEX information.
	 * @param program the program to inspect
	 * @return true if the given program contain CDEX information
	 */
	public final static boolean isCDEX(Program program) {
		if (program != null) {
			try {
				byte[] bytes = new byte[MAGIC.length()];
				program.getMemory().getBytes(program.getMinAddress(), bytes);
				return MAGIC.equals(new String(bytes));
			}
			catch (Exception e) {
				//ignore
			}
		}
		return false;
	}
}
