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
 * Command for renaming a fragment or a module in listing.
 * 
 * 
 */
public class RenameCmd implements Command {

	private String oldName;
	private String newName;
	private boolean isModule;
	private String cmdName;
	private String statusMsg;
	private String treeName;
	private boolean ignoreDuplicateName;
	
	/** 
	 * Construct a new RenameCmd.
	 * @param treeName name of the tree where the module or fragment resides
	 * @param isModule true if a module is to be renamed
	 * @param oldName current name of the module or fragment
	 * @param newName new name for the module or fragment
	 * @param ignoreDuplicateName true means to ignore the exception and
	 * don't do anything
	 */
	public RenameCmd(String treeName, boolean isModule, 
					String oldName, String newName, boolean ignoreDuplicateName) {
		this.treeName = treeName;
		this.isModule = isModule;
		this.oldName = oldName;
		this.newName = newName;
		this.ignoreDuplicateName = ignoreDuplicateName;
		if (isModule) {
			cmdName = "Rename Folder";
		}
		else {
			cmdName = "Rename Fragment";
		}			 					 	
	}
		
	/**
	 * Construct a new RenameCmd.
	 * @param treeName name of the tree where the module or fragment resides
	 * @param isModule true if a module is to be renamed
	 * @param oldName current name of the module or fragment
	 * @param newName new name for the module or fragment
	 */
	public RenameCmd(String treeName, boolean isModule, 
					 String oldName, String newName) {
		this(treeName, isModule, oldName, newName, false);
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	public boolean applyTo(DomainObject obj) {
		Program program = (Program)obj;
		
		return setName(program, oldName, newName);
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
		return cmdName;
	}
	
	private boolean setName(Program program, String oldN, String newN) {
		Listing listing = program.getListing();
		try {
			if (isModule) {
				ProgramModule m = listing.getModule(treeName, oldN);
				m.setName(newN);
			}
			else {
				ProgramFragment f = listing.getFragment(treeName, oldN);
				f.setName(newN);
			}
			return true;
		} catch (DuplicateNameException e) {
			if (ignoreDuplicateName) {
				newName = oldName;
				return true;
			}
			statusMsg = "Name already exists for " + newN;
		}
		return false;
	}

}
