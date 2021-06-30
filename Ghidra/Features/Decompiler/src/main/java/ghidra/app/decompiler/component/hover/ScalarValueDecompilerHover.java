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
package ghidra.app.decompiler.component.hover;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.component.ClangTextField;
import ghidra.app.plugin.core.hover.AbstractScalarOperandHover;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.util.ProgramLocation;

public class ScalarValueDecompilerHover extends AbstractScalarOperandHover
		implements DecompilerHoverService {

	// note: this is relative to other DecompilerHovers; a higher priority gets called first
	// Use high value so this hover gets called first.  The method for determining what the user
	// is hovering in the Decompiler is less then perfect.  We choose to allow the more precise
	// hovers to get a chance to process the request first.
	// We want this hover to go before the data type hovers, due to how that hover decides when it
	// can show a popup, it decides to work when over a scalar.   Having this hover get called
	// first prevents that.
	private static final int PRIORITY = 30;

	private static final String NAME = "Scalar Operand Display";
	private static final String DESCRIPTION =
		"Scalars are shown as 1-, 2-, 4-, and 8-byte values, each in decimal, hexadecimal, and " +
			"as ASCII character sequences.";

	public ScalarValueDecompilerHover(PluginTool tool) {
		super(tool, PRIORITY);
	}

	@Override
	protected String getName() {
		return NAME;
	}

	@Override
	protected String getDescription() {
		return DESCRIPTION;
	}

	@Override
	protected String getOptionsCategory() {
		return GhidraOptions.CATEGORY_DECOMPILER_POPUPS;
	}

	@Override
	public JComponent getHoverComponent(Program program, ProgramLocation programLocation,
			FieldLocation fieldLocation, Field field) {

		if (!enabled) {
			return null;
		}

		if (!(field instanceof ClangTextField)) {
			return null;
		}

		ClangToken token = ((ClangTextField) field).getToken(fieldLocation);
		if (!(token instanceof ClangVariableToken)) {
			return null;
		}

		Varnode vn = ((ClangVariableToken) token).getVarnode();
		if (vn == null) {
			return null;
		}

		long offset = vn.getOffset();
		int sz = vn.getSize();
		HighVariable high = vn.getHigh();
		if (!(high instanceof HighConstant)) {
			return null;
		}

		HighConstant constant = (HighConstant) high;
		boolean isSigned = true;
		DataType dt = constant.getDataType();
		if (dt instanceof AbstractIntegerDataType) {
			isSigned = ((AbstractIntegerDataType) dt).isSigned();
		}

		if (sz > 8) {
			// our Scalar can currently only handle long values
			return null;
		}

		Scalar scalar = new Scalar(sz * 8, offset, isSigned);
		Address addr = token.getMinAddress();
		String formatted = formatScalar(program, addr, scalar);
		return createTooltipComponent(formatted);
	}

}
