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
import ghidra.program.model.listing.*;

/**
 * Command for deleting a variable in a function.
 */
public class DeleteVariableCmd implements Command<Program> {

	private Variable var;

	public DeleteVariableCmd(Variable var) {
		this.var = var;
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return "Delete " + (var instanceof Parameter ? "Parameter" : "Variable");
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(Program program) {
		Function f = var.getFunction();
		if (f == null || f.getProgram() != program) {
			return false;
		}
		f.removeVariable(var);
		return true;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return "";
	}

}
