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
package ghidra.app.plugin.core.decompile.actions;

import docking.action.MenuData;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.util.BigEndianDataConverter;
import ghidra.util.HelpLocation;

/**
 * Convert a selected constant in the decompiler window to a character representation.
 */
public class ConvertCharAction extends ConvertConstantAction {

	public ConvertCharAction(DecompilePlugin plugin) {
		super(plugin, "Convert To Char", EquateSymbol.FORMAT_CHAR);
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionConvert"));
		setPopupMenuData(new MenuData(new String[] { "Char" }, "Decompile"));
	}

	@Override
	public String getMenuPrefix() {
		return "Char: ";
	}

	private static void generateHexEscape(StringBuilder buffer, int value) {
		String res = Integer.toHexString(value);
		int pad = res.length();
		if (pad > 4) {
			pad = 8;
		}
		else if (pad > 2) {
			pad = 4;
		}
		else {
			pad = 2;
		}
		pad = pad - res.length();
		buffer.append("'\\x");
		for (int i = 0; i < pad; ++i) {
			buffer.append('0');
		}
		buffer.append(res.toLowerCase());
		buffer.append('\'');
	}

	@Override
	public String getEquateName(long value, int size, boolean isSigned, Program program) {
		byte[] bytes = new byte[size];
		BigEndianDataConverter.INSTANCE.putValue(value, size, bytes, 0);
		return StringDataInstance.getCharRepresentation(ByteDataType.dataType, bytes, null);
	}

	/**
	 * Return true for any unicode codepoint that needs to be represented with an escape sequence
	 * @param codepoint is the code point value
	 * @return true if the codepoint needs to be escaped
	 */
	private static boolean codePointNeedsEscape(int codepoint) {
		int characterClass = Character.getType(codepoint);
		switch (characterClass) {
			case Character.SPACE_SEPARATOR:
				if (codepoint == 0x20) {
					return false;		// Only the ASCII space is not escaped
				}
				return true;
			case Character.COMBINING_SPACING_MARK:
			case Character.CONTROL:
			case Character.ENCLOSING_MARK:
			case Character.FORMAT:
			case Character.LINE_SEPARATOR:
			case Character.NON_SPACING_MARK:
			case Character.PARAGRAPH_SEPARATOR:
			case Character.PRIVATE_USE:
			case Character.SURROGATE:
			case Character.UNASSIGNED:
				return true;
		}
		return false;
	}

	@Override
	public String getMenuDisplay(long value, int size, boolean isSigned) {
		StringBuilder buffer = new StringBuilder();
		if (size > 1) {
			buffer.append('L');
		}
		if ((size == 1 && value >= 0x7f) || codePointNeedsEscape((int) value)) {
			switch ((int) value) {
				case 0:
					buffer.append("'\\0'");
					break;
				case 7:
					buffer.append("'\\a'");
					break;
				case 8:
					buffer.append("'\\b'");
					break;
				case 9:
					buffer.append("'\\t'");
					break;
				case 10:
					buffer.append("'\\n'");
					break;
				case 11:
					buffer.append("'\\v'");
					break;
				case 12:
					buffer.append("'\\f'");
					break;
				case 13:
					buffer.append("'\\r'");
					break;
				case '"':
					buffer.append("\\\"");
					break;
				case 92:
					buffer.append("\\\\");
					break;
				case '\'':
					buffer.append("\\'");
					break;
				default:
					// Generic unicode escape
					generateHexEscape(buffer, (int) value);
					break;
			}
		}
		else {
			buffer.append('\'').append((char) value).append('\'');
		}
		return buffer.toString();
	}
}
