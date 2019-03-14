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
import util.demangler.GenericDemangledString;

public class DemangledString extends DemangledObject {
	private String string;
	private int length;
	private boolean unicode;

	/**
	 * Construct demangled string.
	 * @param name name associated with this object
	 * @param string string text associated with this object or null.  This is used to establish
	 * label and plate comment if specified.  If null, name will be used as symbol name.
	 * @param length length of string or -1.  Actual string data type applied currently
	 * assumes null terminated string.
	 * @param unicode true if string is a Unicode string.
	 */
	public DemangledString(String name, String string, int length, boolean unicode) {
		setName(name);
		this.string = string;
		this.length = length;
		this.unicode = unicode;
	}

	/**
	 * Construct demangled string from a GenericDemangledString 
	 * @param generic generic demangled string
	 */
	DemangledString(GenericDemangledString generic) {
		super(generic);
		string = generic.getString();
		length = generic.getLength();
		unicode = generic.isUnicode();
	}

	@Override
	public String getSignature(boolean format) {
		StringBuffer buffer = new StringBuffer();
		if (specialPrefix != null) {
			buffer.append(specialPrefix + " for ");
		}
		buffer.append(string);
		if (specialSuffix != null) {
			buffer.append(" " + specialSuffix);
		}
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

		String label = SymbolUtilities.replaceInvalidChars(string, false);
		if (hasLabel(program, address, label)) {
			return true; // Desired symbol already exists here.
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

		// TODO: should we be using length ?
		CreateStringCmd cmd = new CreateStringCmd(address, -1, isUnicode());
		cmd.applyTo(program);

		// unclear what demangled name should be used so apply
		// fabricated string label which is more useful than mangled name
		Symbol demangledSymbol =
			applyDemangledName(buildStringLabel(), address, true, false, program);
		return (demangledSymbol != null);
	}

	private String buildStringLabel() {
		// build string label consistent with dynamic label formatting
		if (specialPrefix != null) {
			return getName();
		}
		int len = string.length();
		StringBuffer buf = new StringBuffer(len);
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
