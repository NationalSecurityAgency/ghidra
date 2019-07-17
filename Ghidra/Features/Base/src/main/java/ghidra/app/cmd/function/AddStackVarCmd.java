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
 * Command to add a stack variable to a function.
 */
public class AddStackVarCmd implements Command {
	private Program program;
	private Address addr;
	private int stackOffset;
	private String name;
	private DataType dataType;
	private SourceType source;
	private String errMsg = "";


	/**
	 * Constructs a new command to add a stack variable to a function.
	 * @param addr initial declaration point of variable.
	 * @param stackOffset offset into the stack for the new variable.
	 * @param name name of the new variable. 
	 * @param dataType variable data-type or null for a default data type of minimal size
	 * @param source the source of this stack variable
	 */
    public AddStackVarCmd(Address addr, int stackOffset, String name, DataType dataType, SourceType source) {
        this.addr = addr;
        this.stackOffset = stackOffset;
        this.name = name;
        this.dataType = dataType;
        this.source = source;
    }

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
    public boolean applyTo(DomainObject obj) {
        program = (Program)obj;
        if (dataType != null) {
        	dataType = dataType.clone(program.getDataTypeManager());
        }
		Function f = program.getListing().getFunctionContaining(addr);
		if (f == null) {
			errMsg="Address not contained within function: " +addr;
			return false;
		}
		StackFrame sf = f.getStackFrame();

		try {
			// TODO: Stack variables only support first use of 0
			// This limitation needs to be fixed along with stack frame editor
			if (sf.createVariable(name, stackOffset, dataType, source) == null) {
				errMsg = "Create stack variable failed";
				return false;
			}
		} catch (DuplicateNameException e) {
			errMsg = "Variable named " + name + " already exists";
			return false;
		} catch (InvalidInputException e) {
			errMsg = e.getMessage();
			return false;
		}
		return true;
    }

    /**
     * @see ghidra.framework.cmd.Command#getName()
     */
    public String getName() {
        return "Create Stack Variable";
    }

    /**
     * @see ghidra.framework.cmd.Command#getStatusMsg()
     */
    public String getStatusMsg() {
        return errMsg;
    }
}
