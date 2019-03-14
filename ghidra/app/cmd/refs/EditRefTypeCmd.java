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
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

/**
 * Command to change the reference type of a memory reference
 */
public class EditRefTypeCmd implements Command {
	private Reference ref;
	private RefType newRefType;
	private ReferenceManager refMgr;
    /**
     * Constructs a new command for changing the reference type of a reference.
     * @param ref the reference whose type it to be changed.
     * @param newRefType the ref type to assign to the reference.
     */
    public EditRefTypeCmd(Reference ref, RefType newRefType) {
    	this.ref = ref;
    	this.newRefType = newRefType;
    }

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
    public boolean applyTo(DomainObject obj) {
    	refMgr = ((Program)obj).getReferenceManager();
    	ref = refMgr.updateRefType(ref, newRefType);
		return true;
    }


    /**
     * @see ghidra.framework.cmd.Command#getStatusMsg()
     */
    public String getStatusMsg() {
        return "";
    }

    /**
     * @see ghidra.framework.cmd.Command#getName()
     */
    public String getName() {
        return "Edit Reference Type";
    }

}
