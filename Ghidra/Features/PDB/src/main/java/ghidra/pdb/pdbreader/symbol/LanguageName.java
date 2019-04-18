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
package ghidra.pdb.pdbreader.symbol;

import ghidra.pdb.AbstractParsableItem;

/**
 * Language name used by certain PDB symbols.
 * @see AbstractCompile2MsSymbol
 * @see Compile3MsSymbol
 * @see CompileFlagsMsSymbol
 */
public class LanguageName extends AbstractParsableItem {

	private static final String idString[] =
		{ "C", "C++", "FORTRAN", "MASM", "Pascal", "Basic", "COBOL", "LINK", "CVTRES", "CVTPGD",
			"C#", "VisualBasic", "ILASM", "Java", "JScript", "MSIL", "HLSL", "???" };

	//==============================================================================================
	private int languageIndex;

	//==============================================================================================
	/**
	 * Constructor for this symbol component.  Takes an int language index argument.
	 * @param languageIndexIn Language index.
	 */
	public LanguageName(int languageIndexIn) {
		this.languageIndex =
			(languageIndexIn >= 0 && languageIndex < idString.length) ? languageIndexIn
					: idString.length - 1;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(idString[languageIndex]);
	}

}
