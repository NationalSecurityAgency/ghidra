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

package ghidra.app.util.bin.format.unixaout;

import ghidra.app.util.opinion.UnixAoutProgramLoader;

/**
 * Represents the content of a single entry in the relocation table format used
 * by the UNIX a.out executable.
 */
public class UnixAoutRelocation {
	public long address;
	public int symbolNum;
	public byte flags;
	public boolean pcRelativeAddressing;
	public byte pointerLength;
	public boolean extern;
	public boolean baseRelative;
	public boolean jmpTable;
	public boolean relative;
	public boolean copy;

	/**
	 * 
	 * @param address First of the two words in the table entry (a 32-bit address)
	 * @param flags Second of the two words in the table entry (containing several bitfields)
	 * @param bigEndian True if big endian; otherwise, false
	 */
	public UnixAoutRelocation(long address, long flags, boolean bigEndian) {
		this.address = (0xFFFFFFFF & address);

		if (bigEndian) {
			this.symbolNum = (int) ((flags & 0xFFFFFF00) >> 8);
			this.flags = (byte) (flags & 0xFF);
			this.pcRelativeAddressing = ((flags & 0x80) != 0);
			this.pointerLength = (byte) (1 << ((flags & 0x60) >> 5));
			this.extern = ((flags & 0x10) != 0);
			this.baseRelative = ((flags & 0x8) != 0);
			this.jmpTable = ((flags & 0x4) != 0);
			this.relative = ((flags & 0x2) != 0);
			this.copy = ((flags & 0x1) != 0);
		}
		else {
			this.symbolNum = (int) (flags & 0x00FFFFFF);
			this.flags = (byte) ((flags & 0xFF000000) >> 24);
			this.pcRelativeAddressing = ((this.flags & 0x01) != 0);
			this.pointerLength = (byte) (1 << ((this.flags & 0x06) >> 1));
			this.extern = ((this.flags & 0x08) != 0);
			this.baseRelative = ((this.flags & 0x10) != 0);
			this.jmpTable = ((this.flags & 0x20) != 0);
			this.relative = ((this.flags & 0x40) != 0);
			this.copy = ((this.flags & 0x80) != 0);
		}
	}

	public String getSymbolName(UnixAoutSymbolTable symtab) {
		if (extern && symbolNum < symtab.size()) {
			return symtab.get(symbolNum).name;
		}
		else if (!extern) {
			return switch (symbolNum) {
				case 4 -> UnixAoutProgramLoader.dot_text;
				case 6 -> UnixAoutProgramLoader.dot_data;
				case 8 -> UnixAoutProgramLoader.dot_bss;
				default -> null;
			};
		}

		return null;
	}
}
