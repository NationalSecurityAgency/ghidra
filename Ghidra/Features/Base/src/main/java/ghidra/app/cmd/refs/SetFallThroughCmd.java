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
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

/**
 * Command for setting the fallthrough property on an instruction.
 */
public class SetFallThroughCmd implements Command {
	Address instAddr;
	Address fallthroughAddr;
    /**
     * Constructs a new command for setting the fallthrough property on an instruction.
     * @param instAddr the address of the instruction whose fallthrought property is
     * to be set.
     * @param fallthroughAddr the address to use for the instructions fallthrough.
     */
    public SetFallThroughCmd(Address instAddr, Address fallthroughAddr) {
    	this.instAddr = instAddr;
    	this.fallthroughAddr = fallthroughAddr;
    }

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
    public boolean applyTo(DomainObject obj) {
    	Program program = (Program)obj;
    	Instruction inst = program.getListing().getInstructionAt(instAddr);
    	inst.setFallThrough(fallthroughAddr);
    	return true;
    }	


    /**
     * @see ghidra.framework.cmd.Command#getName()
     */
    public String getName() {
        return "Set Fall-Through Address";
    }
	/**
	 * 
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	public String getStatusMsg() {
		return null;
	}

}
