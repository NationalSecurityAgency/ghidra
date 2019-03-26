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
package ghidra.app.cmd.function;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Command to add a register variable to a function. 
 *
 */
public class AddRegisterVarCmd implements Command {

	private Program program;
	private Address addr;
	private Register reg;
	private String name;
	private SourceType source;
	private String errMsg = "";
	private DataType dt = null;

	/**
	 * Constructs a new command to add a register variable to a function.
	 * @param addr initial declaration point of variable.
	 * @param reg register for the new variable.
	 * @param name name of the new variable.
	 * @param source the source of this register variable
	 */
	public AddRegisterVarCmd(Address addr, Register reg, String name, SourceType source) {
		this.addr = addr;
		this.reg = reg;
		this.name = name;
		this.source = source;
	}

	/**
	 * Constructs a new command to add a register variable to a function.
	 * @param addr initial declaration point of variable.
	 * @param reg register for the new variable.
	 * @param name name of the new variable.
	 * @param dataType data type to set on the new variable
	 * @param source the source of this register variable
	 */
	public AddRegisterVarCmd(Address addr, Register reg, String name, DataType dataType,
			SourceType source) {
		this.addr = addr;
		this.reg = reg;
		this.name = name;
		this.dt = dataType;
		this.source = source;
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {
		program = (Program) obj;

		Function f = program.getListing().getFunctionContaining(addr);
		if (f == null) {
			errMsg = "Address not contained within function: " + addr;
			return false;
		}

		int firstUseOffset = (int) addr.subtract(f.getEntryPoint());
		try {
			Variable var = new LocalVariableImpl(name, firstUseOffset, dt, reg, program);
			if (f.addLocalVariable(var, source) == null) {
				errMsg = "Create register variable failed";
				return false;
			}
		}
		catch (DuplicateNameException e) {
			errMsg = "Variable named " + name + " already exists";
			return false;
		}
		catch (InvalidInputException e) {
			errMsg = "Variable named " + name + ": " + e.getMessage();
			return false;
		}
		return true;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return "Create Register Variable";
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return errMsg;
	}
}
