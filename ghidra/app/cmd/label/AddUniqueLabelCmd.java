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
package ghidra.app.cmd.label;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.InvalidInputException;

/**
 * Command to add a label. If the label already
 * exists somewhere else, the address is appended to make
 * it unique.
 * @deprecated The need for this class is now unnecessary since duplicate labels are permitted
 */
@Deprecated
public class AddUniqueLabelCmd implements Command {
	private Address address;
	private String name;
	private Namespace namespace;
	private SourceType source;
	private String errorMsg = "";
	private Symbol newSymbol;

	/**
	 * Constructs a new command for adding a label.
	 * @param address address where the label is to be added.
	 * @param name name of the new label. A null name will cause a default label
	 * be added.
	 * @param namespace the namespace of the label. (i.e. the namespace this label is associated with)
	 * @param source the source of this symbol
	 */
	public AddUniqueLabelCmd(Address address, String name, Namespace namespace, SourceType source) {
		this.address = address;
		this.name = name;
		this.namespace = namespace;
		this.source = source;
	}

	/**
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {
		SymbolTable symbolTable = ((Program) obj).getSymbolTable();
		try {
			newSymbol = symbolTable.createLabel(address, name, namespace, source);
			return true;//symbol already exist at this address, just complete
		}
		catch (InvalidInputException e) {
			if ((name == null) || (name.length() == 0)) {
				errorMsg = "You must enter a valid label name";
			}
			else {
				errorMsg = "" + name + " is not a valid label name";
			}
		}
		catch (Exception e) {
			errorMsg = e.getMessage();
		}
		return false;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return errorMsg;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return "Add Unique Label";
	}

	/**
	 * Returns the newly created symbol.
	 * @return the newly created symbol
	 */
	public Symbol getNewSymbol() {
		return newSymbol;
	}
}
