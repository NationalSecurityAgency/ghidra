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

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.symbol.EquateManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.util.exception.*;

/**
 * Renames an equate at a location to a new name.  It will create a new equate if
 * one doesn't already exist with the new name.  If one already exists, it will just
 * add the current location to its list of references.  The old equate will have this
 * reference location removed and will be deleted if it was the last reference.
 */
class RenameEquateCmd implements Command {

	private String oldEquateName;
	private String newEquateName;
	private Enum enoom;
	private Address addr;
	private int opIndex;

	private String msg;

	/**
	 * Constructor
	 * <p>
	 * Renames the old equate with the given new equate name.
	 *
	 * @param oldEquateName the name of the equate that currently exists at the given location.
	 * @param newEquateName the new name for the equate at the given location.
	 * @param addr the address of the equate.
	 * @param opIndex the operand index of the equate.
	 */
	RenameEquateCmd(String oldEquateName, String newEquateName, Address addr, int opIndex) {

		this.oldEquateName = oldEquateName;
		this.newEquateName = newEquateName;
		this.addr = addr;
		this.opIndex = opIndex;
	}

	/**
	 * Constructor
	 * <p>
	 * Uses the fields in the enum as the new equate name for the scalar value. The new equate will
	 * be linked back to the enum. NOTE: only the first field with the matching value will be used
	 * as the new equate name.
	 *
	 * @param oldEquateName the name of the equate that currently exists at the given location.
	 * @param enoom the enoom to use for the enum equates.
	 * @param addr the address of the equate.
	 * @param opIndex the operand index of the equate.
	 */
	RenameEquateCmd(String oldEquateName, Enum enoom, Address addr, int opIndex) {

		this.oldEquateName = oldEquateName;
		this.enoom = enoom;
		this.addr = addr;
		this.opIndex = opIndex;
	}

	/**
	 * The name of the edit action.
	 */
	@Override
	public String getName() {
		return "Rename Equate";
	}

	/**
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.plugintool.PluginTool, ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {
		Program program = ((Program) obj);
		EquateTable etable = program.getEquateTable();
		
		// First make sure there's an entry in the equates table for the equate
		// to be changed (there should always be one).
		Equate fromEquate = etable.getEquate(oldEquateName);
		if (fromEquate == null) {
			msg = "Equate not found: " + oldEquateName;
			return false;
		}
		
		// Get the value behind the equate...for later use.
		long value = fromEquate.getValue();
		
		// See if there are 0 references to this equate.  If so, remove
		// it from the table.
		if (fromEquate.getReferenceCount() <= 1) {
			etable.removeEquate(oldEquateName);
		}
		// Otherwise, there's at least one ref, so remove it.
		else {
			fromEquate.removeReference(addr, opIndex);
		}

		// If the new name is null, then this is an enum equate and we need to add the enum to the 
		// data type manager to generate the correct new formatted equate name.
		if (newEquateName == null && enoom != null) {
			this.enoom = (Enum) program.getDataTypeManager().addDataType(enoom, null);
			this.newEquateName = EquateManager.formatNameForEquate(enoom.getUniversalID(), value);
		}
		// Now move the ref to the new equate name.  To do this, first check the table
		// to see if an entry already exists for this name; if so, use it.  If not, create
		// one.
		Equate toEquate = etable.getEquate(newEquateName);
		if (toEquate == null) {
			try {
				toEquate = etable.createEquate(newEquateName, value);
			}
			catch (DuplicateNameException e) {
				throw new AssertException();
			}
			catch (InvalidInputException e) {
				msg = "Invalid equate name: " + newEquateName;
				return false;
			}
		}
		toEquate.addReference(addr, opIndex);
		return true;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return msg;
	}
}
