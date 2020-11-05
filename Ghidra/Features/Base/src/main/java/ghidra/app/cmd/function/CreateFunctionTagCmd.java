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

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionTagManager;

/**
 * Command for assigning a tag to a function
 */
public class CreateFunctionTagCmd implements Command {

	private String name;
	private String comment;

	/**
	 * Constructor
	 * 
	 * @param name the name of the new tag
	 */
	public CreateFunctionTagCmd(String name) {
		this.name = name;
		this.comment = "";
	}

	/**
	 * Constructor
	 * 
	 * @param name the name of the new tag
	 * @param comment the tag comment
	 */
	public CreateFunctionTagCmd(String name, String comment) {
		this.name = name;
		this.comment = comment;
	}

	@Override
	public boolean applyTo(DomainObject obj) {
		ProgramDB program = (ProgramDB) obj;
		FunctionManager functionManager = program.getFunctionManager();
		FunctionTagManager tagManager = functionManager.getFunctionTagManager();
		tagManager.createFunctionTag(name, comment);
		return true;
	}

	@Override
	public String getName() {
		return "Create Function Tag";
	}

	@Override
	public String getStatusMsg() {
		return null;
	}
}
