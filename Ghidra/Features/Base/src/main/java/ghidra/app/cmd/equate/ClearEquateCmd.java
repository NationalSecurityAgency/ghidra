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
package ghidra.app.cmd.equate;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;

public class ClearEquateCmd implements Command {

	private String equateName;
	private Address addr;
	private int opIndex;

	private String msg;

	public ClearEquateCmd(String equateName, Address addr, int opIndex) {
		this.addr = addr;
		this.opIndex = opIndex;
		this.equateName = equateName;
	}

	@Override
	public String getName() {
		return "Remove Equate";
	}

	@Override
	public boolean applyTo(DomainObject obj) {
		EquateTable equateTable = ((Program) obj).getEquateTable();
		Equate equate = equateTable.getEquate(equateName);

		clearEquate(equate, equateTable);
		return true;
	}

	private void clearEquate(Equate equate, EquateTable equateTable) {
		if (equate == null) {
			return;
		}

		// Remove equate reference
		if (equate.getReferenceCount() <= 1) {
			equateTable.removeEquate(equate.getName());
		}
		else {
			equate.removeReference(addr, opIndex);
		}
	}

	@Override
	public String getStatusMsg() {
		return msg;
	}
}
