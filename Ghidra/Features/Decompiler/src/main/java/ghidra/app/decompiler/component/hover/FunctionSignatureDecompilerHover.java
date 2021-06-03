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

import static ghidra.util.HTMLUtilities.*;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.ClangTextField;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.plugin.core.hover.AbstractConfigurableHover;
import ghidra.app.util.ToolTipUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.util.ProgramLocation;

/**
 * A hover service to show tool tip text for hovering over a function name in the decompiler.
 * The tooltip shows the function signature per the listing.
 */
public class FunctionSignatureDecompilerHover extends AbstractConfigurableHover
		implements DecompilerHoverService {

	private static final String NAME = "Function Signature Display";
	private static final String DESCRIPTION =
		"Show function signatures when hovering over a function name.";
	private static final int PRIORITY = 20;

	protected FunctionSignatureDecompilerHover(PluginTool tool) {
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
		if (token instanceof ClangFuncNameToken) {

			Function function = DecompilerUtils.getFunction(program, (ClangFuncNameToken) token);
			String content = ToolTipUtils.getToolTipText(function, false);
			return createTooltipComponent(content);
		}
		else if (token instanceof ClangVariableToken) {

			// Reference to function-address: "x = &foo;" where 'foo' is a function
			Varnode vn = ((ClangVariableToken) token).getVarnode();
			Scalar scalar = getScalar(vn);
			Function function = getFunctionAtAddress(program, scalar);
			if (function != null) {
				String content = ToolTipUtils.getToolTipText(function, false);
				content = content.replaceFirst(HTML,
					HTML + italic(bold("Reference to Function")) + "<br/><br/>");
				return createTooltipComponent(content);
			}
		}

		return null;
	}

	private Scalar getScalar(Varnode vn) {
		if (vn == null) {
			return null;
		}

		if (!(vn.getHigh() instanceof HighConstant)) {
			return null;
		}

		HighConstant hv = (HighConstant) vn.getHigh();
		long offset = vn.getOffset();
		int sz = vn.getSize();
		boolean isSigned = true;
		if (hv.getDataType() instanceof AbstractIntegerDataType) {
			isSigned = ((AbstractIntegerDataType) hv.getDataType()).isSigned();
		}

		if (sz > 8) {
			return null; // our Scalar can currently only handle long values
		}

		return new Scalar(sz * 8, offset, isSigned);
	}

	private Function getFunctionAtAddress(Program program, Scalar scalar) {

		if (scalar == null) {
			return null;
		}

		long scalarLong = scalar.getValue();
		AddressFactory factory = program.getAddressFactory();
		AddressSpace space = factory.getDefaultAddressSpace();
		try {
			Address asAddress = factory.getAddress(space.getSpaceID(), scalarLong);
			return program.getListing().getFunctionAt(asAddress);
		}
		catch (AddressOutOfBoundsException ex) {
			return null; // scalar is not an address
		}
	}

}
