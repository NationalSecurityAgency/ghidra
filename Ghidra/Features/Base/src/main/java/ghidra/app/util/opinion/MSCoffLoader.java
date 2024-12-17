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
package ghidra.app.util.opinion;

import ghidra.app.util.bin.format.coff.CoffSectionHeader;
import ghidra.app.util.bin.format.pe.SectionHeader;

public class MSCoffLoader extends CoffLoader {
	public final static String MSCOFF_NAME = "MS Common Object File Format (COFF)";

	@Override
	public boolean isMicrosoftFormat() {
		return true;
	}

	@Override
	public String getName() {
		return MSCOFF_NAME;
	}

	@Override
	protected boolean isCaseInsensitiveLibraryFilenames() {
		return true;
	}

	@Override
	protected int getSectionAlignment(CoffSectionHeader section) {
		// Alignment is packed as a 4-bit integer in the flags, value 2^(align_bits - 1)
		int s_flags = section.getFlags();
		int align_bits = (s_flags & SectionHeader.IMAGE_SCN_ALIGN_MASK) >> 20;
		if (align_bits == 0 || align_bits >= 0xF) {
			return 1;
		}
		return 1 << (align_bits - 1);
	}

}
