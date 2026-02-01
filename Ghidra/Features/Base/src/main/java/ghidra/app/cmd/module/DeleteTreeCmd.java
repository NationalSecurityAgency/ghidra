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
import ghidra.program.model.listing.Program;

/**
 * Delete a tree in the program.
 * 
 * 
 */
public class DeleteTreeCmd implements Command<Program> {
	private String treeName;

	/**
	 * Constructor for DeleteTreeCmd.
	 * @param treeName name of tree to delete
	 */
	public DeleteTreeCmd(String treeName) {
		this.treeName = treeName;
	}

	@Override
	public boolean applyTo(Program program) {
		return program.getListing().removeTree(treeName);
	}

	@Override
	public String getStatusMsg() {
		return null;
	}

	@Override
	public String getName() {
		return "Delete " + treeName;
	}

}
