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

import java.math.BigDecimal;

import docking.action.MenuData;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.app.util.HelpTopics;
import ghidra.pcode.floatformat.*;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.HelpLocation;

public class ConvertFloatAction extends ConvertConstantAction {

	public ConvertFloatAction(DecompilePlugin plugin) {
		super(plugin, "Convert To Float", EquateSymbol.FORMAT_FLOAT);
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionConvert"));
		setPopupMenuData(new MenuData(new String[] { "Float" }, "Decompile"));
	}

	@Override
	public String getMenuPrefix() {
		return "Float: ";
	}

	@Override
	public String getMenuDisplay(long value, int size, boolean isSigned, Program program) {
		return getText(value, size, isSigned, program);
	}

	@Override
	public String getEquateName(long value, int size, boolean isSigned, Program program) {
		return getText(value, size, isSigned, program);
	}

	private String getText(long value, int size, boolean isSigned, Program program) {
		DataOrganization organization = program.getDataTypeManager().getDataOrganization();
		int floatSize = organization.getFloatSize();
		Scalar scalar = new Scalar(size * 8, value);
		BigDecimal bd = value(floatSize, scalar);
		if (bd != null) {
			return bd.toString();
		}
		return null;
	}

	private static BigDecimal value(int size, Scalar s) {
		try {
			FloatFormat format = FloatFormatFactory.getFloatFormat(size);
			return format.round(format.decodeBigFloat(s.getBigInteger()));
		}
		catch (UnsupportedFloatFormatException e) {
			return null;
		}
	}
}
