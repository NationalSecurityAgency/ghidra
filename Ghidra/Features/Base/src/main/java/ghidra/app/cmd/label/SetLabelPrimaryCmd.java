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
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Command to make a label the primary label at an address.  Only really
 * makes sense if there is more than one label at the address - otherwise
 * the label will already be primary.
 */
public class SetLabelPrimaryCmd implements Command {
	private SymbolTable st;
	private Address addr;
	private String name;
	private Namespace scope;
	private String errorMsg;

	/**
	 * Constructs a new command for setting the primary state of a label.
	 * @param addr the address of the label to make primary.
	 * @param name the name of the label to make primary.
	 * @param scope the scope of the label to make primary. (the namespace that the label is associated with)
	 */
	public SetLabelPrimaryCmd(Address addr, String name, Namespace scope) {
		this.addr = addr;
		this.name = name;
		this.scope = scope;
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {
		Program program = (Program) obj;
		st = program.getSymbolTable();
		Symbol oldSymbol = st.getPrimarySymbol(addr);
		Symbol newSymbol = st.getSymbol(name, addr, scope);

		if (oldSymbol == null) {
			errorMsg = "No Symbols at address: " + addr;
			return false;
		}
		if (newSymbol == null) {
			// no new symbol - not an error condition if the previous symbol was dynamic.  The
			// assumption here is that the user has performed an operation that did not actually
			// change the state of the symbol, like changing the namespace of a default symbol, 
			// which has no effect
			if (!oldSymbol.isDynamic()) {
				errorMsg =
					"Symbol " + name + " does not exist in namespace " + scope + " at address " +
						addr;
				return false;
			}
			return true;
		}
		if (oldSymbol.getSymbolType() == SymbolType.FUNCTION) {
			if (oldSymbol == newSymbol) {
				return true; // function symbol is already primary
			}
			// keep the function symbol and rename it to the new symbol name;
			// (first have to delete the new symbol).
			String oldName = oldSymbol.getName();
			SourceType oldSource = oldSymbol.getSource();
			Namespace oldParent = oldSymbol.getParentNamespace();
			Namespace parentNamespace = newSymbol.getParentNamespace();
			if (parentNamespace == oldSymbol.getObject()) {
				// parent is the same as the function, so drop the namespace and use global
				parentNamespace = program.getGlobalNamespace();
			}
			st.removeSymbolSpecial(newSymbol);
			try {
				oldSymbol.setNameAndNamespace(name, parentNamespace, newSymbol.getSource());
				// If renamed oldSymbol is now Default source don't keep old name (handles special Thunk rename case)
				if (oldSource != SourceType.DEFAULT && oldSymbol.getSource() != SourceType.DEFAULT) {
					// put the other symbol back using the old namespace and old source
					st.createLabel(addr, oldName, oldParent, oldSource);
				}
				return true;
			}
			catch (DuplicateNameException e) {
				errorMsg = "Duplicate name should not have happened for " + name;
			}
			catch (InvalidInputException e) {
				errorMsg = "InvalidInputException: " + e.getMessage();
			}
			catch (CircularDependencyException e) {
				errorMsg = "CircularDependencyException: " + e.getMessage();
			}
			return false;
		}
		newSymbol.setPrimary();
		return true;
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
		return "Set Primary Label";
	}

}
