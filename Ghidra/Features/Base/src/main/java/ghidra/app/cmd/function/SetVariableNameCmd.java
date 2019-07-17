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
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Command to rename a stack variable.
 */
public class SetVariableNameCmd implements Command {

	private Address fnEntry;
	private String varName;
	private String newName;
	private SourceType source;

	private boolean isParm;
	private String status;

	/**
	 * Constructs a new command to rename a stack/reg variable.
	 * @param var variable to rename
	 * @param newName the new name to give to the stack variable.
	 * @param source the source of this variable name
	 */
	public SetVariableNameCmd(Variable var, String newName, SourceType source) {
		this.fnEntry = var.getFunction().getEntryPoint();
		this.varName = var.getName();
		this.newName = newName;
		this.source = source;
	}

	/**
	 * Constructs a new command to rename a stack/reg variable.
	 * @param fnEntry
	 * @param varName
	 * @param newName
	 * @param source
	 */
	public SetVariableNameCmd(Address fnEntry, String varName, String newName, SourceType source) {
		this.fnEntry = fnEntry;
		this.varName = varName;
		this.newName = newName;
		this.source = source;
	}

	/**
	 *
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {

		if (!(obj instanceof Program)) {
			return false;
		}
		Program p = (Program) obj;

		Function f = p.getFunctionManager().getFunctionAt(fnEntry);
		if (f == null) {
			status = "Function not found";
			return false;
		}

		Symbol s = p.getSymbolTable().getParameterSymbol(varName, f);
		if (s == null) {
			s = p.getSymbolTable().getLocalVariableSymbol(varName, f);
		}
		if (s == null) {
			status = "Variable not found";
			return false;
		}

		Variable var = (Variable) s.getObject();
		isParm = var instanceof Parameter;
		try {
			var.setName(newName, source);
			return true;
		}
		catch (DuplicateNameException e) {
			status = e.getMessage();
		}
		catch (InvalidInputException e) {
			status = e.getMessage();
		}
		return false;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return status;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return "Rename " + (isParm ? "Parameter" : "Variable");
	}

}
