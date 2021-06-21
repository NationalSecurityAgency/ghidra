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
package ghidra.app.cmd.function;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionTag;
import ghidra.util.task.TaskMonitor;

/**
 * Command for deleting a tag from the system
 */
public class DeleteFunctionTagCmd extends BackgroundCommand {

	private String tagName;

	/**
	 * Constructor
	 * 
	 * @param tagName the name of the tag to delete
	 */
	public DeleteFunctionTagCmd(String tagName) {
		this.tagName = tagName;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {

		ProgramDB program = (ProgramDB) obj;
		FunctionManager functionManager = program.getFunctionManager();
		FunctionTag tag = functionManager.getFunctionTagManager().getFunctionTag(tagName);
		if (tag != null) {
			tag.delete();
		}
		return true;
	}

}
