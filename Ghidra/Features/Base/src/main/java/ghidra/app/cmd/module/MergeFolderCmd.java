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
import ghidra.util.Msg;
import ghidra.util.exception.NotEmptyException;
import ghidra.util.exception.NotFoundException;

/**
 * Command to merge a Folder with its Parent folder. Immediate children of
 * the folder are moved to its parent.
 * 
 * 
 */
public class MergeFolderCmd implements Command {

	private String treeName;
	private String folderName;
	private String parentName;
	private String errMsg;

	/**
	 * Construct a new command.
	 * @param treeName name of the tree that this command affects
	 * @param folderName name of the folder (module) that is being merged in
	 * with its parent
	 * @param parentName name of the parent that will end up with children of
	 * the folder named folderName
	 */
	public MergeFolderCmd(String treeName, String folderName, String parentName) {
		this.treeName = treeName;
		this.folderName = folderName;
		this.parentName = parentName;
	}

	/* (non-Javadoc)
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {

		Program program = (Program) obj;
		Listing listing = program.getListing();

		ProgramModule parentModule = listing.getModule(treeName, parentName);
		ProgramModule module = listing.getModule(treeName, folderName);

		if (parentModule == null || module == null) {
			return true; // ignore since the tree has changed since this command was scheduled
		}
		Group[] groups = module.getChildren();

		for (int i = 0; i < groups.length; i++) {

			// first check to make sure that the parent module
			// does not alreay contain tree group

			String name = groups[i].getName();
			ProgramModule m = listing.getModule(treeName, name);
			ProgramFragment f = null;
			try {
				if (m != null && parentModule.contains(m)) {
					module.removeChild(name);
					continue;
				}
				if (m == null) {
					f = listing.getFragment(treeName, name);
					if (parentModule.contains(f)) {
						module.removeChild(name);
						continue;
					}
				}

				parentModule.reparent(name, module);
			}
			catch (NotEmptyException e) {
				Msg.showError(this, null, "Error", "Error merging folder with its parent");
			}
			catch (NotFoundException e) {
				Msg.showError(this, null, "Error", "Error merging folder with its parent");
			}
		}
		// now remove the module from its parent...
		try {
			ProgramModule m = listing.getModule(treeName, folderName);
			ProgramModule[] parents = m.getParents();
			for (int i = 0; i < parents.length; i++) {
				parents[i].removeChild(folderName);
			}
			return true;
		}
		catch (NotEmptyException e) {
			errMsg = e.getMessage();
		}
		return false;
	}

	/* (non-Javadoc)
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return errMsg;
	}

	/* (non-Javadoc)
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return "Merge " + folderName + " with Parent";
	}

}
