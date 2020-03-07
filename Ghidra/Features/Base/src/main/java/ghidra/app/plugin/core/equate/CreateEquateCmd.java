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

import ghidra.app.cmd.equate.SetEquateCmd;
import ghidra.app.context.ListingActionContext;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.symbol.EquateManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

/**
 *Class to handle creating new equates for a selection or the whole program
 */
public class CreateEquateCmd extends BackgroundCommand {

	private CodeUnitIterator iterator; //iterator over selected instructions or null if no selection
	private String equateName; // user defined equate name
	private boolean overwriteExisting; //user defined overwrite option
	private long targetScalarValue;
	private ListingActionContext context;
	private Enum enoom;

	/**
	 * 
	 * @param scalar user defined scalar to search for in program
	 * @param iter the range of code units for which to maybe create equates 
	 * @param equateName user defined name for the new equate to be set
	 * @param overwriteExisting
	 */
	public CreateEquateCmd(Scalar scalar, CodeUnitIterator iter, String equateName,
			boolean overwriteExisting, ListingActionContext context) {
		super("Create New Equate", true /* has progress */, true /* can cancel */,
			false /* is modal */);
		this.targetScalarValue = scalar.getValue();
		this.iterator = iter;
		this.equateName = equateName;
		this.overwriteExisting = overwriteExisting;
		this.context = context;
	}

	/**
	 * 
	 * @param scalar user defined scalar to search for in program
	 * @param iter the range of code units for which to maybe create equates 
	 * @param enoom the enum to use for formatting the equate name
	 * @param overwriteExisting
	 */
	public CreateEquateCmd(Scalar scalar, CodeUnitIterator iter, Enum enoom,
			boolean overwriteExisting, ListingActionContext context) {
		super("Create New Equate", true /* has progress */, true /* can cancel */,
			false /* is modal */);
		this.targetScalarValue = scalar.getValue();
		this.iterator = iter;
		this.overwriteExisting = overwriteExisting;
		this.context = context;
		this.enoom = enoom;
	}

	@Override
	public boolean applyTo(DomainObject domain, TaskMonitor monitor) {

		monitor.setIndeterminate(true);
		monitor.setMessage("Creating Equate");

		while (iterator.hasNext() && !monitor.isCancelled()) {
			CodeUnit cu = iterator.next();
			if (cu instanceof Instruction) {
				maybeCreateEquate(domain, (Instruction) cu);
			}
			else if (cu instanceof Data) {
				maybeCreateEquate(domain, (Data) cu);
			}
		}
		return true;
	}

	private void maybeCreateEquate(DomainObject domain, Data data) {

		if (!data.isDefined()) {
			return;
		}

		Object val = data.getValue();
		if (!(val instanceof Scalar)) {
			return;
		}

		Scalar scalar = (Scalar) val;
		if (scalar.getValue() != targetScalarValue) {
			return;
		}

		int opIndex = getOperandIndex();
		createEquate(domain, data, opIndex, scalar);
	}

	private void maybeCreateEquate(DomainObject domain, Instruction instruction) {
		for (int opIndex = 0; opIndex < instruction.getNumOperands(); opIndex++) {
			Object[] opObjects = instruction.getOpObjects(opIndex);
			for (Object opObject : opObjects) {
				if (!(opObject instanceof Scalar)) {
					continue;
				}

				Scalar scalar = (Scalar) opObject;
				if (scalar.getValue() != targetScalarValue) {
					continue;
				}

				createEquate(domain, instruction, opIndex, scalar);
			}
		}
	}

	private void createEquate(DomainObject domain, CodeUnit codeUnit, int opIndex,
			Scalar scalar) {


		EquateTable equateTable = codeUnit.getProgram().getEquateTable();
		Address address = codeUnit.getAddress();
		Equate curEquate = equateTable.getEquate(address, opIndex, targetScalarValue);

		if (equateName == null && enoom != null) {
			this.equateName = generateFormattedEquateName();
		}

		if (curEquate == null) {
			Command cmd = new SetEquateCmd(equateName, address, opIndex, targetScalarValue);
			cmd.applyTo(domain);
		}
		else if (overwriteExisting) {
			Command cmd = new RenameEquateCmd(curEquate.getName(), equateName, address, opIndex);
			cmd.applyTo(domain);
		}
	}
	
	private String generateFormattedEquateName() {
		Program program = context.getProgram();
		Enum enumWithId = (Enum) program.getDataTypeManager().addDataType(enoom, null);
		String formattedName =
			EquateManager.formatNameForEquate(enumWithId.getUniversalID(), targetScalarValue);
		return formattedName;
	}

	/**
	 * Get the operand index at the location
	 *
	 * @return 0-3 for a good operand location, -1 otherwise
	 */
	private int getOperandIndex() {
		ProgramLocation location = context.getLocation();
		if (location instanceof OperandFieldLocation) {
			return ((OperandFieldLocation) location).getOperandIndex();
		}
		return -1;
	}
}
