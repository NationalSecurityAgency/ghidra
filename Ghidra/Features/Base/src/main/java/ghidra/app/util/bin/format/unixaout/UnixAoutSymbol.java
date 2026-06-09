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

/**
 * Represents the content of a single entry in the symbol table format used by
 * the UNIX a.out executable.
 */
public class UnixAoutSymbol {

	public enum SymbolType {
		N_UNDF, N_ABS, N_TEXT, N_DATA, N_BSS, N_INDR, N_FN, N_STAB, UNKNOWN
	}

	public enum SymbolKind {
		AUX_FUNC, AUX_OBJECT, AUX_LABEL, UNKNOWN
	}

	public long nameStringOffset;
	public String name;
	public SymbolType type;
	public SymbolKind kind;
	public byte otherByte;
	public short desc;
	public long value;
	public boolean isExt;

	public UnixAoutSymbol(long nameStringOffset, byte typeByte, byte otherByte, short desc,
			long value) {
		this.nameStringOffset = nameStringOffset;
		this.otherByte = otherByte;
		this.desc = desc;
		this.value = value;
		this.isExt = (typeByte & 1) == 1;

		this.type = switch (typeByte & 0xfe) {
			case 0 -> SymbolType.N_UNDF;
			case 2 -> SymbolType.N_ABS;
			case 4 -> SymbolType.N_TEXT;
			case 6 -> SymbolType.N_DATA;
			case 8 -> SymbolType.N_BSS;
			case 10 -> SymbolType.N_INDR;
			default -> (typeByte & 0xfe) >= 0x20 ? SymbolType.N_STAB : SymbolType.UNKNOWN;
		};

		this.kind = switch (otherByte & 0x0f) {
			case 1 -> SymbolKind.AUX_OBJECT;
			case 2 -> SymbolKind.AUX_FUNC;
			case 3 -> SymbolKind.AUX_LABEL;
			default -> SymbolKind.UNKNOWN;
		};
	}
}
