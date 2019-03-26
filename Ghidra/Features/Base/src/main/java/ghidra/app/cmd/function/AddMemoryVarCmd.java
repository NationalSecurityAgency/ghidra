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
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Command to add a memory variable to a function.
 */
public class AddMemoryVarCmd implements Command {
	private Program program;
	private Address memAddr;
	private Address firstUseAddr;
	private String name;
	private DataType dt;
	private SourceType source;
	private String errMsg = "";

	/**
	 * Constructs a new command to add a memory variable to a function.
	 * @param memAddr memory variable address
	 * @param firstUseAddr initial declaration point of variable.
	 * @param name name of the new variable. 
	 * @param source the source of this memory variable
	 */
	public AddMemoryVarCmd(Address memAddr, Address firstUseAddr, String name, SourceType source) {
		this.memAddr = memAddr;
		this.firstUseAddr = firstUseAddr;
		this.name = name;
		this.source = source;
	}

	/**
	 * Constructs a new command to add a memory variable to a function.
	 * @param memAddr memory variable address
	 * @param firstUseAddr initial declaration point of variable.
	 * @param name name of the new variable. 
	 * @param dt variable data type
	 * @param source the source of this memory variable
	 */
	public AddMemoryVarCmd(Address memAddr, Address firstUseAddr, String name, DataType dt,
			SourceType source) {
		this.memAddr = memAddr;
		this.firstUseAddr = firstUseAddr;
		this.name = name;
		this.dt = dt;
		this.source = source;
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {
		program = (Program) obj;

		Function f = program.getListing().getFunctionContaining(firstUseAddr);
		if (f == null) {
			errMsg = "Address not contained within function: " + firstUseAddr;
			return false;
		}
		int firstUseOffset = (int) firstUseAddr.subtract(f.getEntryPoint());
		try {
			Variable var = new LocalVariableImpl(name, firstUseOffset, dt, memAddr, program);
			if (f.addLocalVariable(var, source) == null) {
				errMsg = "Create memory variable failed";
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
		return "Create Memory Variable";
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return errMsg;
	}
}
