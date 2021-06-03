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
package ghidra.app.util.bin.format.pdb2.pdbreader.symbol;

import java.util.HashMap;
import java.util.Map;

/**
 * Language name used by certain PDB symbols.
 * @see AbstractCompile2MsSymbol
 * @see Compile3MsSymbol
 * @see CompileFlagsMsSymbol
 */
public enum LanguageName {

	INVALID("???", -1),
	C("C", 0),
	CPP("C++", 1),
	FORTRAN("FORTRAN", 2),
	MASM("MASM", 3),
	PASCAL("Pascal", 4),
	BASIC("Basic", 5),
	COBOL("COBOL", 6),
	LINK("LINK", 7),
	CVTRES("CVTRES", 8),
	CVTPGD("CVTPGD", 9),
	CSHARP("C#", 10),
	VISUALBASIC("VisualBasic", 11),
	ILASM("ILASM", 12),
	JAVA("Java", 13),
	JSCRIPT("JScript", 14),
	MSIL("MSIL", 15),
	HLSL("HLSL", 16);

	private static final Map<Integer, LanguageName> BY_VALUE = new HashMap<>();
	static {
		for (LanguageName val : values()) {
			BY_VALUE.put(val.value, val);
		}
	}

	public final String label;
	public final int value;

	@Override
	public String toString() {
		return label;
	}

	public static LanguageName fromValue(int val) {
		return BY_VALUE.getOrDefault(val, INVALID);
	}

	private LanguageName(String label, int value) {
		this.label = label;
		this.value = value;
	}

}
