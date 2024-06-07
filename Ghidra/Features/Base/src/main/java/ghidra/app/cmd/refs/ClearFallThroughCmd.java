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
package ghidra.app.cmd.refs;

import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

/**
 * Command to clear a fallthrough.
 */
public class ClearFallThroughCmd implements Command<Program> {
	Address instAddr;

	/**
	 * Constructs a new command to remove a fallthrough.
	 * @param instAddr the address of the instruction from which to remove the
	 * fallthrough.
	 */
	public ClearFallThroughCmd(Address instAddr) {
		this.instAddr = instAddr;
	}

	@Override
	public boolean applyTo(Program program) {
		Instruction inst = program.getListing().getInstructionAt(instAddr);
		inst.clearFallThroughOverride();
		return true;
	}

	@Override
	public String getName() {
		return "Clear Fall-through Override";
	}

	@Override
	public String getStatusMsg() {
		return null;
	}

}
