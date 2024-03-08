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
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

/**
 * Command for removing external references.
 */
public class RemoveExternalRefCmd implements Command<Program> {

	private Address fromAddr;
	private int opIndex;

	/**
	 * Constructs a new command for removing an external reference.
	 * @param fromAddr the address of the codeunit making the external reference.
	 * @param opIndex the operand index.
	 */
	public RemoveExternalRefCmd(Address fromAddr, int opIndex) {
		this.fromAddr = fromAddr;
		this.opIndex = opIndex;
	}

	@Override
	public boolean applyTo(Program program) {
		ReferenceManager refMgr = program.getReferenceManager();

		Reference[] refs = refMgr.getReferencesFrom(fromAddr, opIndex);
		for (Reference ref : refs) {
			if (ref.isExternalReference()) {
				refMgr.delete(ref);
			}
		}

		return true;
	}

	@Override
	public String getStatusMsg() {
		return null;
	}

	@Override
	public String getName() {
		return "Remove External Reference";
	}

}
