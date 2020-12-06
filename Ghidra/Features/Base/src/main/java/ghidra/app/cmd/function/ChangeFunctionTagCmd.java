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
import ghidra.program.model.listing.*;

/**
 * Updates the name or comment field for a given function tag
 */
public class ChangeFunctionTagCmd implements Command {

	private final int field;
	private final String tagName;
	private final String newVal;

	private String errorMsg = "";

	public static final int TAG_NAME_CHANGED = 0;
	public static final int TAG_COMMENT_CHANGED = 1;

	/**
	 * Constructor
	 * 
	 * @param tagName the name of the tag to change
	 * @param newVal the new value to set
	 * @param field the field to set
	 */
	public ChangeFunctionTagCmd(String tagName, String newVal, int field) {
		if (field != TAG_NAME_CHANGED && field != TAG_COMMENT_CHANGED) {
			throw new IllegalArgumentException("Invalid field: " + field);
		}
		this.tagName = tagName;
		this.newVal = newVal;
		this.field = field;
	}

	@Override
	public boolean applyTo(DomainObject obj) {
		ProgramDB program = (ProgramDB) obj;
		FunctionManager functionManager = program.getFunctionManager();
		FunctionTagManager tagManager = functionManager.getFunctionTagManager();
		FunctionTag tag = tagManager.getFunctionTag(tagName);

		if (tag == null) {
			errorMsg = "Function Tag not found: " + tagName;
			return false;
		}

		if (field == TAG_NAME_CHANGED) {
			tag.setName(newVal);
		}
		else {
			tag.setComment(newVal);
		}

		return true;
	}

	@Override
	public String getStatusMsg() {
		return errorMsg;
	}

	@Override
	public String getName() {
		return "Change Function Tag";
	}
}
