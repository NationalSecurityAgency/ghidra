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
import ghidra.util.exception.NotFoundException;

/**
 * Command to reorder children in a module.
 * 
 * 
 */
public class ReorderModuleCmd implements Command {
	private String moduleName;
	private String childName;
	private int index;
	private String statusMsg; 
	private String treeName;
	/**
	 * Constructor for ReorderModuleCmd.
	 * @param treeName tree that contains the parent module identified by
	 * the parentModuleName
	 * @param parentModuleName name of the module with the children to reorder
	 * @param childName name of the child to move to the new index
	 * @param index new index for the child
	 */
	public ReorderModuleCmd(String treeName, String parentModuleName, 
							String childName, int index) {
		this.treeName = treeName;
		moduleName = parentModuleName;
		this.childName = childName;
		this.index = index;
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	public boolean applyTo(DomainObject obj) {
		Program program = (Program)obj;
		Listing listing = program.getListing();
		ProgramModule m = listing.getModule(treeName, moduleName);
		try {
			m.moveChild(childName, index);
			return true;
		} catch (NotFoundException e) {
			statusMsg = e.getMessage();	
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
		return "Reorder";
	}

}
