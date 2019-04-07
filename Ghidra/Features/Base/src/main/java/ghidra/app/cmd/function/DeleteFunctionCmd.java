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
package ghidra.app.cmd.function;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

/**
 * Command for clearing a function at an address.  
 */
public class DeleteFunctionCmd implements Command {
	private Address entry;
	private boolean ignoreMissingFunction;

	/**
	 * Constructs a new command for deleting a function.
	 * @param entry entry point address for the function to be deleted.
	 */
	public DeleteFunctionCmd(Address entry) {
		this(entry, true);
	}

	public DeleteFunctionCmd(Address entry, boolean ignoreMissingFunction) {
		this.entry = entry;
		this.ignoreMissingFunction = ignoreMissingFunction;
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return "Delete Function";
	}

	/**
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {
		Program program = (Program) obj;
		// save off the function signature
		//   get the body, comment, stack, return type
		Listing listing = program.getListing();
		Function func = listing.getFunctionAt(entry);
		if (func == null) {
			if (ignoreMissingFunction) {
				return true;		// consider it a success
			}
			return false;
		}

		if (!entry.isExternalAddress()) {
			func.promoteLocalUserLabelsToGlobal();
		}

		listing.removeFunction(entry);

		return true;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return "";
	}

}
