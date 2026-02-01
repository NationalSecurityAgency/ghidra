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
 * A simple command to set the stack purge size of a function.
 * 
 * 
 * @since  Tracker Id 548
 */
public class SetFunctionPurgeCommand implements Command<Program> {
	private Function function;
	private int functionPurge;

	/**
	 * Creates a new command that will set the given purge size on the given
	 * function.
	 * 
	 * @param function The function on which to set the purge size.
	 * @param newPurge The new stack purge size.
	 */
	public SetFunctionPurgeCommand(Function function, int newPurge) {
		this.function = function;
		this.functionPurge = newPurge;
	}

	@Override
	public boolean applyTo(Program program) {
		function.setStackPurgeSize(functionPurge);
		return true;
	}

	@Override
	public String getStatusMsg() {
		return "";
	}

	@Override
	public String getName() {
		return "Set Function Purge";
	}
}
