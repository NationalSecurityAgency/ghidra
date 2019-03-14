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
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;


/**
 * Command for changing the scope of a label.
 * The scope is the namespace that the label is associated with.
 */
public class SetLabelNamespaceCmd implements Command {
	private SymbolTable st;
	private Address addr;
	private String name;
	private Namespace oldNamespace;
	private Namespace newNamespace;
	private String errorMsg = "";	
	
	/**
	 * Constructs a new command for changing the scope of a label.
	 * @param addr the address of the label to be changed.
	 * @param name the name of the label to be changed.
	 * @param oldNamespace the current scope of the label that will be changed.
	 * @param newNamespace the new scope of the label.
	 */
	public SetLabelNamespaceCmd(Address addr, String name, 
				Namespace oldNamespace, Namespace newNamespace) {
		this.addr = addr;
		this.name = name;
		this.oldNamespace = oldNamespace;
		this.newNamespace = newNamespace;
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	public boolean applyTo(DomainObject obj) {
		st = ((Program)obj).getSymbolTable();

		Symbol s = st.getSymbol(name, addr, oldNamespace);
		if (s == null) {
			errorMsg = "No symbol named "+name+" found at address "+addr+
					" in namespace "+oldNamespace;
			return false;
		}
		try {
			s.setNamespace(newNamespace); 
			return true;
		}catch (DuplicateNameException e) {
			errorMsg = "Symbol named "+name+" already exists in namespace "+newNamespace;
		} catch (InvalidInputException e) {
			errorMsg = e.getMessage();
		} catch (CircularDependencyException e) {
			errorMsg = e.getMessage();
		}	
		return false;
	}


	/**
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	public String getName() {
		return "Set Namespace";
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	public String getStatusMsg() {
		return errorMsg;
	}

}
