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
package ghidra.app.util.bin.format.dwarf.macro.entry;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.util.bin.format.dwarf.attribs.DWARFNumericAttribute;
import ghidra.app.util.bin.format.dwarf.attribs.DWARFStringAttribute;
import ghidra.app.util.bin.format.dwarf.macro.DWARFMacroHeader;
import ghidra.app.util.bin.format.dwarf.macro.DWARFMacroOpcode;
import ghidra.util.exception.AssertException;

/**
 * Represents a "#define ...." macro element.
 */
public class DWARFMacroDefine extends DWARFMacroInfoEntry {
	//@formatter:off
	private static final Pattern PARSEMACROREGEX = Pattern.compile(
		"([^( ]+)" +                    // "NAME" group=1 
		"|([^( ]+) (.+)" +              // "NAME VALUE" group=2,3
		"|([^( ]+)\\(([^)]+)\\) (.*)"); // "NAME(arg, arg) BODY" group=4,5,6
	//@formatter:on

	public record MacroInfo(String macro, String symbolName, List<String> parameters,
			boolean isFunctionLike, String definition) {
		@Override
		public String toString() {
			if (macro.isEmpty()) {
				return "";
			}
			StringBuilder sb = new StringBuilder("Macro Symbol: ");
			sb.append(symbolName);
			sb.append(" ");
			if (isFunctionLike) {
				sb.append("(function-like) ");
				sb.append("parameters[%d]: ".formatted(parameters.size()));
				for (int i = 0; i < parameters.size(); i++) {
					sb.append(parameters.get(i));
					if (i != parameters.size() - 1) {
						sb.append(",");
					}
				}
				sb.append(" ");
			}
			else {
				sb.append("(object-like) ");
			}
			sb.append("definition: ");
			sb.append(definition.isEmpty() ? "-none-" : "\"%s\"".formatted(definition));
			return sb.toString();
		}

	}

	public static MacroInfo parseMacro(String macroString) {
		Matcher m = PARSEMACROREGEX.matcher(macroString);
		if (!m.matches() || m.group(1) != null) {
			return new MacroInfo(macroString, macroString, List.of(), false, "");
		}
		if (m.group(2) != null) {
			return new MacroInfo(macroString, m.group(2), List.of(), false, m.group(3));
		}
		if (m.group(5) != null) {
			return new MacroInfo(macroString, m.group(4), Arrays.asList(m.group(5).split(",")),
				true, m.group(6));
		}
		throw new AssertException();
	}

	public DWARFMacroDefine(int lineNumber, String defineString, DWARFMacroHeader parent) {
		super(DWARFMacroOpcode.DW_MACRO_define, parent);
		operandValues[0] = new DWARFNumericAttribute(lineNumber, operandDef(0));
		operandValues[1] = new DWARFStringAttribute(defineString, operandDef(1));
	}

	public DWARFMacroDefine(DWARFMacroInfoEntry other) {
		super(other);
	}

	public int getLineNumber() throws IOException {
		return getOperand(0, DWARFNumericAttribute.class).getUnsignedIntExact();
	}

	public String getMacro() throws IOException {
		return getOperand(1, DWARFStringAttribute.class).getValue(macroHeader.getCompilationUnit());
	}

	public MacroInfo getMacroInfo() throws IOException {
		return parseMacro(getMacro());
	}

	@Override
	public String toString() {
		try {
			return "%s: line: %d, %s".formatted(getName(), getLineNumber(), getMacroInfo());
		}
		catch (IOException e) {
			return super.toString();
		}
	}
}
