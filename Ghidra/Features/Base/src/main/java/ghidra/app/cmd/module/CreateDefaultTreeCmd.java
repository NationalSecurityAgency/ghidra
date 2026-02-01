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
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.DuplicateNameException;

/**
 * 
 * Command to create a root in the program; the root module has
 * fragments named the same as the memory blocks.
 * 
 * 
 */
public class CreateDefaultTreeCmd implements Command<Program> {

	private String treeName;
	private String statusMsg;

	/**
	 * Constructor for CreateDefaultTreeCmd. 
	 * @param treeName name of the tree to create
	 */
	public CreateDefaultTreeCmd(String treeName) {
		this.treeName = treeName;
	}

	@Override
	public boolean applyTo(Program program) {
		Listing listing = program.getListing();
		try {
			listing.createRootModule(treeName);
			renameFragments(program, treeName);
			return true;
		}
		catch (DuplicateNameException e) {
			statusMsg = e.getMessage();
		}
		return false;
	}

	/**
	 * Create a tree in the program with the given tree name.
	 * @param program program
	 * @param treeName tree name
	 * @return Module root module for the new tree
	 * @throws DuplicateNameException if treeName already exists
	 */
	static ProgramModule createRootModule(Program program, String treeName)
			throws DuplicateNameException {

		Listing listing = program.getListing();
		ProgramModule root = listing.createRootModule(treeName);
		renameFragments(program, treeName);
		return root;
	}

	/**
	 * Method renameFragments.
	 */
	private static void renameFragments(Program program, String treeName) {
		Listing listing = program.getListing();
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		for (MemoryBlock block : blocks) {
			ProgramFragment fragment = listing.getFragment(treeName, block.getStart());
			try {
				fragment.setName(block.getName());
			}
			catch (DuplicateNameException e) {
				// ignore
			}
		}
	}

	@Override
	public String getStatusMsg() {
		return statusMsg;
	}

	@Override
	public String getName() {
		return "Create Tree " + treeName;
	}

}
