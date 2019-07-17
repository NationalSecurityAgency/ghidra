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
package ghidra.app.cmd.equate;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Command for setting an equate at a location.
 */
public class SetEquateCmd implements Command {

	private String equateName;
	private Address addr;
	private int opIndex;
	private long equateValue;
	private Equate equate;

	private String msg;

	/**
	 * Constructor
	 * @param equateName the name of the equate to applied or removed at this location.
	 * @param addr the address of the current location.
	 * @param opIndex the operand index of the current location.
	 * @param equateValue the numeric value at the current location.
	 */
	public SetEquateCmd(String equateName, Address addr, int opIndex, long equateValue) {

		this.equateName = equateName;
		this.addr = addr;
		this.opIndex = opIndex;
		this.equateValue = equateValue;
	}

	/**
	 * The name of the edit action.
	 */
	@Override
	public String getName() {
		return "Set Equate";
	}

	@Override
	public boolean applyTo(DomainObject obj) {
		EquateTable equateTable = ((Program) obj).getEquateTable();
		equate = equateTable.getEquate(equateName);


		if (existsWithDifferentValue(equate)) {
			msg =
				"Equate named " + equateName + " already exists with value of " +
					equate.getValue() + ".";
			return false;
		}

		if (equate == null) {
			// Create new equate
			try {
				equate = equateTable.createEquate(equateName, equateValue);
			}
			catch (DuplicateNameException e) {
				msg = "Equate named " + equateName + " already exists";
				return false;
			}
			catch (InvalidInputException e) {
				msg = "Invalid equate name: " + equateName;
				return false;
			}
		}

		// Add reference to existing equate
		equate.addReference(addr, opIndex);
		return true;
	}

	private boolean existsWithDifferentValue(Equate e) {
		return e != null && e.getValue() != equateValue;
	}

	public Equate getEquate() {
		return equate;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return msg;
	}

}
