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
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

/**
 * Command for assigning a tag to a function. Executing this will pop up a dialog
 * allowing the user to assign tags to a function.
 */
public class AddFunctionTagCmd implements Command {

	private Address entryPoint;
	private String tagName;
	private String errorMsg = "";

	/**
	 * Constructor
	 * 
	 * @param tagName the name of the tag to add
	 * @param entryPoint the function address
	 */
	public AddFunctionTagCmd(String tagName, Address entryPoint) {
		this.tagName = tagName;
		this.entryPoint = entryPoint;
	}

	@Override
	public boolean applyTo(DomainObject obj) {
		ProgramDB program = (ProgramDB) obj;
		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionAt(entryPoint);

		if (function == null) {
			errorMsg = "Function not found at: " + entryPoint.toString();
			return false;
		}

		return function.addTag(tagName);
	}

	@Override
	public String getStatusMsg() {
		return errorMsg;
	}

	@Override
	public String getName() {
		return "Add Tag To Function";
	}
}
