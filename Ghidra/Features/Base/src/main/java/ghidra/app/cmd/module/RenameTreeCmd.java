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
package ghidra.app.cmd.module;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.DuplicateNameException;

/**
 * 
 * Command to rename a tree in a program; this does not affect
 * the root module of the tree.
 * 
 * 
 */
public class RenameTreeCmd implements Command {

	private String oldName;
	private String newName;
	private Program program;
	private String statusMsg;
	 
	/**
	 * Constructor for RenameTreeCmd.
	 * @param oldName old name of the tree
	 * @param newName new name of the tree
	 */
	public RenameTreeCmd(String oldName, String newName) {
		this.oldName = oldName;
		this.newName = newName;
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	public boolean applyTo(DomainObject obj) {
		program = (Program)obj;
		Listing listing = program.getListing();
		try {
			listing.renameTree(oldName, newName);
			return true;
		} catch (DuplicateNameException e) {
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
		return "Rename Tree View";
	}

}
