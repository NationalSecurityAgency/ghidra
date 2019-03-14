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
package ghidra.app.cmd.module;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Command to create a folder in a program tree.
 */
public class CreateFolderCommand implements Command {

	private String name;
	private String statusMsg;
	private String parentName;
	private String treeName;
	
	/**
	 * @param treeName name of the tree where the new Module will reside
	 * @param name of the new Module
	 * @param parentName name of the parent module
	 */
	public CreateFolderCommand(String treeName, String name, String parentName) {
		this.treeName = treeName;
		this.name = name;
		this.parentName = parentName;
	}

	/**
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	public boolean applyTo(DomainObject obj) {
		Program program = (Program)obj;
		Listing listing = program.getListing();
		ProgramModule m = listing.getModule(treeName, parentName);
		if (m == null) {
			statusMsg = "Folder named " + parentName + " does not exist";
			return false;
		}		
		
		try {
			m.createModule(name); 
			return true;
		} catch (DuplicateNameException e) {
			statusMsg = name + " already exists";
		}
		return false;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	public String getStatusMsg() {
		return statusMsg;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	public String getName() {
		return "Create Folder"; 
	}

}
