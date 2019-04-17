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
package ghidra.app.cmd.refs;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

/**
 * Command for removing memory references.
 */
public class RemoveReferenceCmd implements Command {

	private Address fromAddr;
	private Address toAddr;
	private int opIndex;

	private String status;

	/**
	 * Constructs a new command for removing a memory reference.
	 * @param ref the reference to remove
	 */
	public RemoveReferenceCmd(Reference ref) {
		this.fromAddr = ref.getFromAddress();
		this.toAddr = ref.getToAddress();
		this.opIndex = ref.getOperandIndex();
	}

	/**
	 * Constructs a new command for removing a memory reference.
	 * @param fromAddr the address of the codeunit making the reference.
	 * @param toAddr the address being referred to.
	 * @param opIndex the operand index.
	 */
	public RemoveReferenceCmd(Address fromAddr, Address toAddr, int opIndex) {
		this.fromAddr = fromAddr;
		this.toAddr = toAddr;
		this.opIndex = opIndex;
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {
		Program p = (Program) obj;
		ReferenceManager refMgr = p.getReferenceManager();
		Reference ref = refMgr.getReference(fromAddr, toAddr, opIndex);
		if (ref != null) {
			refMgr.delete(ref);
			fixupReferencedVariable(p, ref);
			return true;
		}

		status = "Reference not found";
		return false;
	}

	/**
	 * Fixup referenced local function variable after removing a reference to it.
	 * Method returns immediately if toAddr is not a stack or register address.
	 * <ol>
	 * <li>If a referenced DEFAULT variable has no remaining references it will be removed.</li>
	 * <li>The firstUseOffset associated with a referenced local variable will be updated
	 * to reflect the minimum reference offset within the function.</li>
	 * </ol>
	 * @param p program
	 * @param ref reference
	 */
	static void fixupReferencedVariable(Program p, Reference deletedRef) {
		Variable var = p.getReferenceManager().getReferencedVariable(deletedRef);
		if (var != null) {
			Symbol s = var.getSymbol();
			if (s != null && !(var instanceof Parameter) && s.getSource() == SourceType.DEFAULT &&
				s.getReferenceCount() == 0) {
				// Remove orphaned DEFAULT variable
				s.delete();
			}
		}
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return status;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return "Remove Reference";
	}

}
