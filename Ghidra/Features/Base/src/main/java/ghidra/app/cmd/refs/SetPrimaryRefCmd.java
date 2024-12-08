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
 * Command class for setting a reference to be primary.  Any other
 * reference that was primary at that address will no longer be primary.
 */
public class SetPrimaryRefCmd implements Command<Program> {

	private Address fromAddr;
	private int opIndex;
	private Address toAddr;
	private boolean isPrimary;

	private String status;

	/**
	 * Creates a command for setting whether or not a reference is the primary reference.
	 * If isPrimary is true, any other reference that was primary at that 
	 * address will no longer be primary.
	 * @param ref the reference
	 * @param isPrimary true to make the reference primary, false to make it non-primary
	 */
	public SetPrimaryRefCmd(Reference ref, boolean isPrimary) {
		this(ref.getFromAddress(), ref.getOperandIndex(), ref.getToAddress(), isPrimary);
	}

	/**
	 * Creates a command for setting whether or not a reference is the primary reference.
	 * If isPrimary is true, any other reference that was primary at that 
	 * address will no longer be primary.
	 * @param fromAddr the address of the codeunit making the reference.
	 * @param opIndex the operand index.
	 * @param toAddr the address being referred to.
	 * @param isPrimary true to make the reference primary, false to make it non-primary
	 */
	public SetPrimaryRefCmd(Address fromAddr, int opIndex, Address toAddr, boolean isPrimary) {
		this.fromAddr = fromAddr;
		this.opIndex = opIndex;
		this.toAddr = toAddr;
		this.isPrimary = isPrimary;
	}

	@Override
	public boolean applyTo(Program program) {

		ReferenceManager refMgr = program.getReferenceManager();
		Reference ref = refMgr.getReference(fromAddr, toAddr, opIndex);

		if (ref == null) {
			status = "Reference not found";
			return false;
		}

		refMgr.setPrimary(ref, isPrimary);

		return true;
	}

	@Override
	public String getStatusMsg() {
		return status;
	}

	@Override
	public String getName() {
		return "Set Primary Reference";
	}

}
