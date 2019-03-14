/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.cmd.label;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

/**
 * Command to delete a label
 */
public class DeleteLabelCmd implements Command {

	private Address addr;
	private String name;
	private Namespace scope;
	private String errorMsg;
	private ExternalEntryCmd externalEntryCmd;

	/**
	 * Constructs a new command for deleting a label or function variable.
	 * @param addr address of the label to be deleted.
	 * @param name name of the label to be deleted.
	 * @param scope the scope of the label to delete. (i.e. the namespace the label to delete is associated with)
	 */
	public DeleteLabelCmd(Address addr, String name, Namespace scope) {
		this.addr = addr;
		this.name = name;
		this.scope = scope;
	}

	/**
	 * Constructs a new command for deleting a global symbol
	 * @param addr address of the label to be deleted.
	 * @param name name of the label to be deleted.
	 */
	public DeleteLabelCmd(Address addr, String name) {
		this(addr, name, null);
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {
		SymbolTable st = ((Program) obj).getSymbolTable();
		Symbol s = st.getSymbol(name, addr, scope);
		if (s == null) {
			errorMsg = "Symbol " + name + " not found!";
			return false;
		}
		if (s.isDynamic()) {
			errorMsg =
				"Deleting the dynamic symbol \"" + name + "\" @ " + addr + " is not allowed.";
			return false;
		}
		if (s.isExternalEntryPoint() && s.isPrimary()) {
			if (st.getSymbols(s.getAddress()).length == 1) {
				externalEntryCmd = new ExternalEntryCmd(addr, false);
				externalEntryCmd.applyTo(obj);
			}
		}
		boolean success = st.removeSymbolSpecial(s);
		if (!success) {
			errorMsg = "Couldn't delete the symbol \"" + name + "\" @ " + addr + ".";
		}
		return success;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return "Delete Label";
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return errorMsg;
	}
}
