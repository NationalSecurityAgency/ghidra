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

/**
 * Convert a selected constant in the decompiler to an octal representation.
 */
public class ConvertOctAction extends ConvertConstantAction {

	public ConvertOctAction(DecompilePlugin plugin) {
		super(plugin, "Convert To Octal", EquateSymbol.FORMAT_OCT);
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionConvert"));
		setPopupMenuData(new MenuData(new String[] { "Octal" }, "Decompile"));
	}

	@Override
	public String getMenuPrefix() {
		return "Octal: ";
	}

	@Override
	public String getMenuDisplay(long value, int size, boolean isSigned) {
		Scalar scalar = new Scalar(size * 8, value);
		if (isSigned) {
			long v = scalar.getSignedValue();
			String valueStr = Long.toString(v, 8);
			if (v < 0) {
				// use of substring removes '-' prefix for negative value
				return "-0" + valueStr.substring(1);
			}
			return "0" + valueStr;
		}
		String valueStr = Long.toOctalString(scalar.getUnsignedValue());
		return "0" + valueStr;
	}

	@Override
	public String getEquateName(long value, int size, boolean isSigned, Program program) {
		Scalar scalar = new Scalar(size * 8, value);
		return Long.toOctalString(scalar.getUnsignedValue()) + "o";
	}
}
