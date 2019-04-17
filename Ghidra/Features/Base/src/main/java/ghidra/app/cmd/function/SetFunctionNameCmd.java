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
import ghidra.program.model.symbol.SourceType;

/**
 * Command to set the name of a function.
 */
public class SetFunctionNameCmd implements Command {
    private Address entry;
    private String  name;
	private String msg;    
	private SourceType source;
    /**
     * Constructs a new command for setting the name of a function.
     * @param entry the address of the function to be renamed.
     * @param newName the new name for the function.
	 * @param source the source of this function name
     */
    public SetFunctionNameCmd(Address entry, String newName, SourceType source) {
        this.entry = entry;
		this.name = newName;
		this.source = source;
    }        
	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	public boolean applyTo(DomainObject obj) {
		Program program = (Program)obj;
		     
        if (name.length() <= 0) {
            name = null;
        }

        Function f = program.getListing().getFunctionAt(entry);
        if (f == null) {
            return true;
        }
		try {
			f.setName(name, source);
		}
		catch (Exception e) {
			msg = e.getMessage();
			return false;
		}
		return true;

    }
    
	/**
	 * 
	 * @see ghidra.framework.cmd.Command#getName()
	 */
    public String getName() {
        return "Rename Function";
    }
    
    
	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	public String getStatusMsg() {
		return msg;
	}

}
