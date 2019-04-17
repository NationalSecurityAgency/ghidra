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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Command to set the Function's Repeatable Comment.
 */
public class SetFunctionRepeatableCommentCmd implements Command {
    private Address entry;
    private String  newRepeatableComment;
    
    /**
     * Constructs a new command for setting the Repeatable comment.
     * @param entry address of the function for which to set a Repeatablecomment.
     * @param newRepeatableComment comment to set as the function Repeatable comment.
     */
    public SetFunctionRepeatableCommentCmd(Address entry, String newRepeatableComment) {
        this.entry = entry;
        this.newRepeatableComment = newRepeatableComment;
    }
    
	/**
	 * 
	 * @see ghidra.framework.cmd.Command#getName()
	 */
    public String getName() {
        return "Set Function Repeatable Comment";
    }
    
	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	public boolean applyTo(DomainObject obj) {
		Program program = (Program)obj;
        Function f = program.getListing().getFunctionAt(entry);
        if (f != null) {
	        f.setRepeatableComment(newRepeatableComment);
        }
        return true;	
    }

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	public String getStatusMsg() {
		return "";
	}

}
