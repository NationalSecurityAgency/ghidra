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
package ghidra.app.cmd.refs;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Command class for adding stack references to a program.
 */
public class AddStackRefCmd implements Command {
	
	private Address fromAddr;
	private int opIndex;
	private int stackOffset;
	private RefType refType;
	private SourceType source;
	
	private String status;
	
    /**
     * Constructs a new command for adding a stack reference.
	 * @param fromAddr "from" address within a function
	 * @param opIndex operand index
	 * @param stackOffset stack offset of the reference
	 * @param source the source of this reference
     */
    public AddStackRefCmd(Address fromAddr, int opIndex, int stackOffset, SourceType source) {
     	this.fromAddr = fromAddr;
     	this.opIndex = opIndex;
     	this.stackOffset = stackOffset;
     	this.source = source;
    }
    
    /**
     * Constructs a new command for adding a stack reference.
	 * @param fromAddr "from" address within a function
	 * @param opIndex operand index
	 * @param stackOffset stack offset of the reference
	 * @param refType reference type (e.g., STACK_READ or STACK_WRITE)
	 * @param source the source of this reference
     */
    public AddStackRefCmd(Address fromAddr, int opIndex, int stackOffset, RefType refType, SourceType source) {
     	this.fromAddr = fromAddr;
     	this.opIndex = opIndex;
     	this.stackOffset = stackOffset;
     	this.refType = refType;
     	this.source = source;
    }

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
    public boolean applyTo(DomainObject obj) {
		Program p = (Program)obj;
		
		Function f = p.getFunctionManager().getFunctionContaining(fromAddr);
		if (f == null) {
			status = "Stack reference may only be created within a function";
			return false;
		}
		
		if (refType == null) {
			refType = RefTypeFactory.getDefaultStackRefType(p.getListing().getCodeUnitAt(fromAddr), opIndex);
		}
		
//		if (refType.isWrite()) {
			Variable var = f.getStackFrame().getVariableContaining(stackOffset);
			if (var == null) {
				try {
					f.getStackFrame().createVariable(null, stackOffset, null, SourceType.DEFAULT);
				}
				catch (DuplicateNameException e) {
				}
				catch (InvalidInputException e) {
					status = e.getMessage();
					return false;
				}
				catch (AddressOutOfBoundsException e) {
					status = e.getMessage();
					return false;
				}
//			}
		}
		p.getReferenceManager().addStackReference(fromAddr, opIndex, stackOffset, refType, source);
		return true;
    }

    /**
     * @see ghidra.framework.cmd.Command#getStatusMsg()
     */
    public String getStatusMsg() {
        return status;
    }

    /**
     * @see ghidra.framework.cmd.Command#getName()
     */
    public String getName() {
        return "Add Stack Reference";
    }

}
