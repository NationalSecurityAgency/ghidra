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
package ghidra.app.util.demangler;

import ghidra.app.cmd.data.CreateStringCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;
import ghidra.util.task.TaskMonitor;

public class DemangledString extends DemangledObject {
	private String string;
	private int length;
	private boolean unicode;

	/**
	 * Construct demangled string.
	 * @param mangled the source mangled string
	 * @param originalDemangled the original demangled string
	 * @param name name associated with this object
	 * @param string string text associated with this object or null.  This is used to establish
	 * label and plate comment if specified.  If null, name will be used as symbol name.
	 * @param length length of string or -1.  Actual string data type applied currently
	 * assumes null terminated string.
	 * @param unicode true if string is a Unicode string.
	 */
	public DemangledString(String mangled, String originalDemangled, String name, String string,
			int length, boolean unicode) {
		super(mangled, originalDemangled);
		setName(name);
		this.string = string;
		this.length = length;
		this.unicode = unicode;
	}

	@Override
	public String getSignature(boolean format) {
		StringBuilder buffer = new StringBuilder();
		if (specialPrefix != null) {
			buffer.append(specialPrefix);
		}
		buffer.append(string);
		return buffer.toString();
	}

	private static boolean hasLabel(Program program, Address address, String label) {

		SymbolTable symbolTable = program.getSymbolTable();
		for (Symbol s : symbolTable.getSymbols(address)) {
			if (label.equals(s.getName())) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean applyTo(Program program, Address address, DemanglerOptions options,
			TaskMonitor monitor) throws Exception {

		String label = buildStringLabel();
		if (hasLabel(program, address, label)) {
			return true; // This string has already been applied
		}

		if (!super.applyTo(program, address, options, monitor)) {
			return false;
		}

		Symbol s = program.getSymbolTable().getPrimarySymbol(address);
		if (s != null && s.getSymbolType() == SymbolType.FUNCTION) {
			Msg.error(this,
				"Failed to demangled string at " + address + " due to existing function");
			return false;
		}

		CreateStringCmd cmd = new CreateStringCmd(address, -1, isUnicode());
		cmd.applyTo(program);

		Symbol demangledSymbol =
			applyDemangledName(label, address, true, false, program);
		return (demangledSymbol != null);
	}

	private String buildStringLabel() {

		if (specialPrefix != null) {
			// a 'special prefix' implies that the author wishes to apply the string exactly as-is
			return getName();
		}

		// build string label consistent with dynamic label formatting
		int len = string.length();
		StringBuilder buf = new StringBuilder(len);
		for (int i = 0; i < len; ++i) {
			char c = string.charAt(i);
			if (StringUtilities.isDisplayable(c) && (c != ' ')) {
				buf.append(c);
			}
			else {
				buf.append('_');
			}
		}
		String prefix = isUnicode() ? "u_" : "s_";
		return prefix + buf.toString();
	}

	/**
	 * Returns the demangled string.
	 * @return the demangled string
	 */
	public String getString() {
		return string;
	}

	/**
	 * Returns the length in bytes of the demangled string.
	 * @return the length in bytes of the demangled string
	 */
	public int getLength() {
		return length;
	}

	/**
	 * Returns true if the demangled string is unicode.
	 * @return true if the demangled string is unicode
	 */
	public boolean isUnicode() {
		return unicode;
	}
}
