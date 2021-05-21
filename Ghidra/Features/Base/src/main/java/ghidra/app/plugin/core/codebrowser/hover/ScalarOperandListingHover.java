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
package ghidra.app.plugin.core.codebrowser.hover;

import java.util.List;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.hover.AbstractScalarOperandHover;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;

public class ScalarOperandListingHover extends AbstractScalarOperandHover
		implements ListingHoverService {

	private static final int PRIORITY = 20;
	private static final String NAME = "Scalar Operand Display";
	private static final String DESCRIPTION =
		"Scalars are shown as 1-, 2-, 4-, and 8-byte values, each in decimal, hexadecimal, and " +
			"as ASCII character sequences.";

	public ScalarOperandListingHover(PluginTool tool) {
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
		return GhidraOptions.CATEGORY_BROWSER_POPUPS;
	}

	@Override
	public JComponent getHoverComponent(Program program, ProgramLocation programLocation,
			FieldLocation fieldLocation, Field field) {

		if (!enabled || programLocation == null) {
			return null;
		}

		if (!(programLocation instanceof OperandFieldLocation)) {
			return null;
		}

		Address a = programLocation.getAddress();
		Instruction instruction = program.getListing().getInstructionAt(a);
		if (instruction == null) {
			return null;
		}

		OperandFieldLocation operandLocation = (OperandFieldLocation) programLocation;
		Object operand = getOperand(operandLocation, instruction);
		if (!(operand instanceof Scalar)) {
			return null;
		}

		String formatted =
			formatScalar(instruction.getProgram(), instruction.getAddress(), (Scalar) operand);
		return createTooltipComponent(formatted);
	}

	private Object getOperand(OperandFieldLocation loc, Instruction instruction) {
		int opIndex = loc.getOperandIndex();
		Object[] operands = instruction.getOpObjects(opIndex);
		if (operands.length == 1) {
			return operands[0];
		}

		InstructionPrototype prototype = instruction.getPrototype();
		List<Object> list =
			prototype.getOpRepresentationList(opIndex, instruction.getInstructionContext());
		if (list == null) {
			return null;
		}
		// make sure operand sub-opIndex is in bounds
		int subOpIndex = loc.getSubOperandIndex();
		if (subOpIndex < 0 || subOpIndex >= list.size()) {
			return null;
		}
		return list.get(subOpIndex);
	}

}
