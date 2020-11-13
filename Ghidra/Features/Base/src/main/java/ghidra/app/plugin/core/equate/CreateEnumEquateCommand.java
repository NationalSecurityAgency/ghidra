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

import java.util.*;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.symbol.EquateManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class CreateEnumEquateCommand extends BackgroundCommand {

	private AddressSetView addresses;
	private Enum enoom;
	private Program program;
	private boolean shouldDoOnSubOps;
	private EquateTable equateTable;

	/**
	 * Constructor
	 * 
	 * @param program The program to use
	 * @param addresses The addresses to apply an enum to
	 * @param enoom The enum to apply equates with
	 * @param shouldDoOnSubOps true if the enum should also be applied to the sub-operands.
	 */
	public CreateEnumEquateCommand(Program program, AddressSetView addresses, Enum enoom,
			boolean shouldDoOnSubOps) {
		this.program = Objects.requireNonNull(program);
		this.addresses = Objects.requireNonNull(addresses);
		this.enoom = Objects.requireNonNull(enoom);
		this.shouldDoOnSubOps = shouldDoOnSubOps;
	}

	@Override
	public String getName() {
		return "Create Enum Equate Command";
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {

		monitor.setIndeterminate(true);
		monitor.setMessage("Installing Equate");

		equateTable = program.getEquateTable();
		try {
			applyEnum(monitor);
		}
		catch (CancelledException e) {
			return false;
		}
		return true;
	}

	private void applyEnum(TaskMonitor monitor) throws CancelledException {

		Listing listing = program.getListing();
		InstructionIterator it = listing.getInstructions(addresses, true);
		monitor.initialize(addresses.getNumAddresses());
		while (it.hasNext()) {

			monitor.checkCanceled();

			Instruction instruction = it.next();
			processsEquates(instruction);
			monitor.incrementProgress(instruction.getLength());
		}
	}

	private void processsEquates(Instruction instruction) {
		for (int opIndex = 0; opIndex < instruction.getNumOperands(); opIndex++) {

			if (!shouldDoOnSubOps) {
				// Only apply equates to scalars that are not contained in sub operands.
				Scalar scalar = instruction.getScalar(opIndex);
				maybeCreateEquateOnScalar(instruction, opIndex, scalar);
			}
			else {
				// Apply equates to scalars in the sub operands as well.
				List<?> subOperands = instruction.getDefaultOperandRepresentationList(opIndex);
				for (Object subOp : subOperands) {
					maybeCreateEquateOnScalar(instruction, opIndex, subOp);
				}
			}
		}
	}

	private void maybeCreateEquateOnScalar(Instruction instruction, int opIndex,
			Object operandRepresentation) {

		if (!(operandRepresentation instanceof Scalar)) {
			return;
		}

		Scalar scalar = (Scalar) operandRepresentation;

		int enoomLength = enoom.getLength();
		boolean anyValuesMatch = Arrays.stream(enoom.getValues()).anyMatch(enumValue -> {
			return scalar.equals(new Scalar(enoomLength * 8, enumValue, scalar.isSigned()));
		});

		if (!anyValuesMatch) {
			return;
		}

		if (program.getDataTypeManager().findDataTypeForID(enoom.getUniversalID()) == null) {
			enoom = (Enum) program.getDataTypeManager().addDataType(enoom, null);
		}

		Address addr = instruction.getAddress();
		removeUnusedEquates(opIndex, scalar, addr);

		long value = scalar.getValue();
		String equateName = EquateManager.formatNameForEquate(enoom.getUniversalID(), value);
		Equate equate = getOrCreateEquate(equateName, value);
		equate.addReference(addr, opIndex);
	}

	private void removeUnusedEquates(int opIndex, Scalar scalar, Address addr) {
		Equate existingEquate = equateTable.getEquate(addr, opIndex, scalar.getValue());
		if (existingEquate != null) {
			if (existingEquate.getReferenceCount() <= 1) {
				equateTable.removeEquate(existingEquate.getName());
			}
		}
	}

	private Equate getOrCreateEquate(String name, long value) {
		Equate equate = equateTable.getEquate(name);
		if (equate != null) {
			return equate;
		}

		try {
			equate = equateTable.createEquate(name, value);
		}
		catch (DuplicateNameException | InvalidInputException e) {
			// These should not happen:
			// Duplicate will not happen since we checked for the existence first; Invalid 
			// can't happen since we built the name ourselves (we are assuming)
			Msg.error(this, "Unexpected error creating equate", e);  // just in case
		}
		return equate;
	}

}
