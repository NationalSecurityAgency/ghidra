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
package ghidra.app.util.bin.format.plan9aout;

/**
 * Represents the content of a single entry in the symbol table format used by
 * the PLAN9 a.out executable.
 */
public class Plan9AoutSymbol {

	public enum SymbolType {
		N_TEXT, N_LEAF, N_DATA, N_BSS, N_AUTO, N_PARAM, N_FRAME, N_FILE, N_PATH, N_LINE, UNKNOWN
	}

	public String name;
	public SymbolType type;
	public long value;
	public boolean isExt;

	public Plan9AoutSymbol(String name, byte typeByte, long value) {
		this.name = name;
		this.value = value;
		this.isExt = (typeByte & 0x20) == 0;

		this.type = switch (((int)typeByte) & 0xff) {
			case 0x80+'t', 0x80+'T' -> SymbolType.N_TEXT;
			case 0x80+'l', 0x80+'L' -> SymbolType.N_LEAF;
			case 0x80+'d', 0x80+'D' -> SymbolType.N_DATA;
			case 0x80+'b', 0x80+'B' -> SymbolType.N_BSS;
			case 0x80+'a' -> SymbolType.N_AUTO;
			case 0x80+'p' -> SymbolType.N_PARAM;
			case 0x80+'m' -> SymbolType.N_FRAME;
			case 0x80+'f' -> SymbolType.N_FILE;
			case 0x80+'z' -> SymbolType.N_PATH;
			case 0x80+'Z' -> SymbolType.N_LINE;
			default -> SymbolType.UNKNOWN;
		};
	}
}
