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
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.HelpLocation;
import ghidra.util.StringUtilities;

/**
 * Convert a selected constant in the decompiler to a binary representation.
 */
public class ConvertBinaryAction extends ConvertConstantAction {

	public ConvertBinaryAction(DecompilePlugin plugin) {
		super(plugin, "Convert To Binary", EquateSymbol.FORMAT_BIN);
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionConvert"));
		setPopupMenuData(new MenuData(new String[] { "Binary" }, "Decompile"));
	}

	@Override
	public String getMenuPrefix() {
		return "Binary: ";
	}

	@Override
	public String getMenuDisplay(long value, int size, boolean isSigned) {
		Scalar scalar = new Scalar(size * 8, value);
		long v;
		String prefix = "0b";
		if (isSigned) {
			v = scalar.getSignedValue();
			if (v < 0) {
				v = -v;
				prefix = "-0b";
			}
		}
		else {
			v = scalar.getUnsignedValue();

		}
		String bitString = Long.toBinaryString(v);
		int bitlen = bitString.length();
		if (bitlen <= 8) {
			bitlen = 8;
		}
		else if (bitlen <= 16) {
			bitlen = 16;
		}
		else if (bitlen <= 32) {
			bitlen = 32;
		}
		else {
			bitlen = 64;
		}
		return prefix + StringUtilities.pad(bitString, '0', bitlen);
	}

	@Override
	public String getEquateName(long value, int size, boolean isSigned, Program program) {
		String valueStr = Long.toBinaryString(value);
		valueStr = StringUtilities.pad(valueStr, '0', size * 8);
		return valueStr + "b";
	}
}
