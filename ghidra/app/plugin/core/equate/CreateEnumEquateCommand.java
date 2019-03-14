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
package ghidra.app.plugin.core.equate;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.EquateTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class CreateEnumEquateCommand extends BackgroundCommand {

	private AddressSetView addresses;
	private Enum enoom;
	private Program program;
	private boolean shouldDoOnSubOps;

	/**
	 * Constructor
	 * 
	 * @param program The program to use
	 * @param addresses The addresses to apply an enum to
	 * @param enoom The enum to apply equates with
	 * @param shouldIncludeTypes True if the equate name should include the enum name.
	 * @param shouldDoOnSubOps True if the enum should also be applied to the sub-operands.
	 */
	public CreateEnumEquateCommand(Program program, AddressSetView addresses, Enum enoom,
			boolean shouldDoOnSubOps) {
		this.program = program;
		this.addresses = addresses;
		this.enoom = enoom;
		this.shouldDoOnSubOps = shouldDoOnSubOps;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {

		EquateTable et = program.getEquateTable();
		try {
			et.applyEnum(addresses, enoom, monitor, shouldDoOnSubOps);
		}
		catch (CancelledException e) {
			return false;
		}
		return true;
	}

	@Override
	public String getName() {
		return "Create Enum Equate Command";
	}

}
