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
package ghidra.file.formats.android.wdex;

import ghidra.program.model.listing.Program;

/**
 * Android .WDEX files.
 * 
 * https://android.googlesource.com/platform/art/+/master/runtime/vdex_file.h
 */
public final class WdexConstants {

	/**
	  * <pre>
	  * static constexpr uint8_t kVdexInvalidMagic[] = { 'w', 'd', 'e', 'x' };
	  * </pre>
	 */
	public final static String MAGIC = "wdex";

	public final static String kVdexInvalidMagic = MAGIC;

	/**
	 * Returns true if the given program contain WDEX information.
	 */
	public final static boolean isWDEX(Program program) {
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
