/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.memory;

import ghidra.app.plugin.core.clear.ClearCmd;
import ghidra.app.plugin.core.clear.ClearOptions;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.RollbackException;
import ghidra.util.task.TaskMonitor;

public class UninitializedBlockCmd extends BackgroundCommand {

	private MemoryBlock block;
	private Program program;

	public UninitializedBlockCmd(Program program, MemoryBlock block) {
		super("Unitialize Memory Block", false, true, true);
		this.program = program;
		this.block = block;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) throws RuntimeException {
		ClearOptions clearOptions = new ClearOptions(false);
		clearOptions.setClearCode(true);
		clearOptions.setClearDefaultReferences(true);
		clearOptions.setClearFunctions(true);
		clearOptions.setClearAnalysisReferences(true);
		clearOptions.setClearImportReferences(true);
		clearOptions.setClearUserReferences(true);
		ClearCmd clearCmd =
			new ClearCmd(new AddressSet(block.getStart(), block.getEnd()), clearOptions);
		if (!clearCmd.applyTo(program, monitor)) {
			setStatusMsg(clearCmd.getStatusMsg());
			return false;
		}
		if (monitor.isCancelled()) {
			throw new RollbackException("Operation cancelled");
		}
		try {
			program.getMemory().convertToUninitialized(block);
		}
		catch (Exception e) {
			setStatusMsg(e.getMessage());
			return false;
		}
		return true;
	}
}
