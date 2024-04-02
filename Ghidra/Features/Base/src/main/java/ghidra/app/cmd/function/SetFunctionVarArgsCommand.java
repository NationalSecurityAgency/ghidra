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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * A simple command to set whether or not a function has VarArgs.
 */
public class SetFunctionVarArgsCommand implements Command<Program> {
	private Function function;
	private boolean hasVarArgs;

	/**
	 * Creates a new command that will set whether or not there are VarArgs on the given
	 * function.
	 * 
	 * @param function The function on which to set whether or not there are VarArgs.
	 * @param hasVarArgs true if you want to set this function to have VarArgs.
	 */
	public SetFunctionVarArgsCommand(Function function, boolean hasVarArgs) {
		this.function = function;
		this.hasVarArgs = hasVarArgs;
	}

	@Override
	public boolean applyTo(Program program) {
		function.setVarArgs(hasVarArgs);
		return true;
	}

	@Override
	public String getStatusMsg() {
		return "";
	}

	@Override
	public String getName() {
		return "Set Function VarArgs";
	}
}
