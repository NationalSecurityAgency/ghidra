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
package ghidra.app.plugin.core.equate;

import java.util.List;
import java.util.Optional;

import ghidra.app.cmd.equate.ClearEquateCmd;
import ghidra.app.cmd.equate.SetEquateCmd;
import ghidra.app.context.ListingActionContext;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.docking.settings.Settings;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.ProgramSelection;
import ghidra.util.task.TaskMonitor;

public class ConvertCommand extends BackgroundCommand {
	private Program program;
	private AbstractConvertAction action;
	private ListingActionContext context;

	private String msg;

	/**
	 * Constructor for the command to convert scalars and data to the user chosen format. The
	 * command will work at a single address or over a selection in the case where the current
	 * location refers to an instruction.  
	 * <br>
	 * Data convert only supports signed/unsigned and defined FormatSettingsDefinitions
	 * on data whose data type is based upon the AbstractIntegerDataType.
	 * 
	 * @param action The action to pull information from
	 * @param context The action context
	 */
	public ConvertCommand(AbstractConvertAction action, ListingActionContext context) {
		this.action = action; // Need this to call the applyEquate function.
		this.context = context;
		this.program = context.getProgram();
	}

	@Override
	public String getName() {
		return "Convert Command";
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {

		try {
			CodeUnit cu = action.plugin.getCodeUnit(context);
			if (cu instanceof Data) {
				return applyDataSettings((Data) cu);
			}

			if (context.hasSelection()) {
				msg = applyEquateOverRange(context.getSelection());
				return msg == null;
			}

			Instruction instruction = (Instruction) context.getCodeUnit();
			int opIndex = action.plugin.getOperandIndex(context);
			msg = applyEquate(instruction, opIndex);
		}
		catch (Exception e) {
			msg = "Exception applying the Convert: " + e.getMessage();
		}

		return msg == null;
	}

	private boolean applyDataSettings(Data data)
			throws CodeUnitInsertionException, DataTypeConflictException {

		DataType dt = data.getBaseDataType();
		Settings settings = data;
		Settings defaultSettings = dt.getDefaultSettings();
		if (!(Scalar.class.equals(data.getValueClass())) ||
			!(dt instanceof AbstractIntegerDataType)) {
			msg = "Unsupported data type for convert: " + data.getDataType().getDisplayName();
			return false;
		}

		int formatChoice = action.getFormatChoice();

		// Only change data-type when decimal signed/unsigned mode differs from data type
		// since other formats are always unsigned regardless of data type
		if (formatChoice == FormatSettingsDefinition.DECIMAL) {
			AbstractIntegerDataType numDt = (AbstractIntegerDataType) dt;
			if (action.isSignedChoice()) {
				if (!numDt.isSigned()) {
					DataType signedDataType = numDt.getOppositeSignednessDataType();
					createData(data, signedDataType);
				}
			}
			else if (numDt.isSigned()) {
				DataType unsignedDataType = numDt.getOppositeSignednessDataType();
				createData(data, unsignedDataType);
			}
		}

		if (FormatSettingsDefinition.DEF.getChoice(defaultSettings) == formatChoice) {
			FormatSettingsDefinition.DEF.clear(settings);
		}
		else {
			FormatSettingsDefinition.DEF.setChoice(settings, formatChoice);
		}

		return true;
	}

	private void createData(Data data, DataType unsignedDataType)
			throws CodeUnitInsertionException, DataTypeConflictException {
		Listing listing = data.getProgram().getListing();
		Address addr = data.getAddress();
		listing.clearCodeUnits(addr, data.getMaxAddress(), false);
		listing.createData(addr, unsignedDataType);
	}

	private String applyEquateOverRange(ProgramSelection selection) {
		InstructionIterator it = program.getListing().getInstructions(context.getSelection(), true);
		String errorMessage = null;
		for (Instruction instruction : it) {
			for (int i = 0; i < instruction.getNumOperands(); i++) {
				String m = applyEquate(instruction, i);
				if (errorMessage == null && m != null) {
					errorMessage = m;
				}
			}
		}
		return errorMessage;
	}

	/*
	 * Create a new equate. If already created with a different value, then we can't do anything. 
	 * If equate name is null, i.e. selection is not letter or digit, then do nothing
	 */
	private String applyEquate(Instruction instruction, int opIndex) {
		if (instruction == null || opIndex == -1) {
			return null;
		}

		Scalar scalar = grabMatchingScalar(instruction, opIndex);
		if (scalar == null) {
			return null;
		}

		String equateName = action.convertToString(program, scalar, false);
		if (equateName.isEmpty()) {
			return null;
		}

		// Check for same named equate with different value.
		EquateTable equateTable = program.getEquateTable();
		Equate eqt = equateTable.getEquate(equateName);
		if (eqt != null && valuesAreDifferent(eqt, scalar)) {
			return "Couldn't convert to " + equateName + ". " + "Equate named " + equateName +
				" already exists with value of " + eqt.getValue() + ".";
		}

		Address address = instruction.getAddress();
		List<Equate> equates = equateTable.getEquates(address, opIndex);

		// First, clear any existing equates with the same value
		for (Equate equate : equates) {
			if (!valuesAreDifferent(equate, scalar)) {
				// Clears matching equates 
				ClearEquateCmd cmd = new ClearEquateCmd(equate.getName(), address, opIndex);
				cmd.applyTo(program);
			}
		}

		// check if default hex scalar format applies
		if (action.getFormatChoice() == FormatSettingsDefinition.HEX) {
			if (scalar.getSignedValue() >= 0 || action.isSignedChoice() == scalar.isSigned()) {
				return null;
			}
		}

		// Then, add the new equate
		SetEquateCmd cmd = new SetEquateCmd(equateName, address, opIndex, scalar.getValue());
		if (!cmd.applyTo(program)) {
			return "Couldn't convert to " + equateName + ". " + cmd.getStatusMsg();
		}

		return null;
	}

	/**
	 * Gets a scalar that matches the value of the scalar at the cursor location.
	 * @param instruction The instruction to search
	 * @param opIndex The operand index to look at
	 * @return A scalar that matches the value of the scalar at the cursor location, or null if no
	 * such scalar can be found.
	 */
	private Scalar grabMatchingScalar(Instruction instruction, int opIndex) {
		Scalar scalarAtCursor = action.plugin.getScalar(context);
		Scalar scalar = instruction.getScalar(opIndex);

		if (scalarAtCursor.equals(scalar)) {
			return scalar;
		}

		if (scalar == null) {
			// Checks the sub-operands for any scalars.
			List<?> opObjects = instruction.getDefaultOperandRepresentationList(opIndex);
			//@formatter:off
			Optional<Scalar> match = opObjects.stream()
				.filter(Scalar.class::isInstance)
				.map(Scalar.class::cast)
				.filter(s -> s.equals(scalarAtCursor))
				.findAny()
				;
			//@formatter:on

			if (match.isPresent()) {
				return match.get();
			}
		}

		return null;
	}

	@Override
	public String getStatusMsg() {
		return msg;
	}

	private boolean valuesAreDifferent(Equate equate, Scalar scalar) {
		long value = equate.getValue();
		return value != scalar.getSignedValue() && value != scalar.getUnsignedValue();
	}

}
