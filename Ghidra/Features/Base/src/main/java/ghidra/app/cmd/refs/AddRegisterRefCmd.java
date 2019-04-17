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
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;

import java.util.List;

/**
 * Command class to add a register reference to the program.
 */
public class AddRegisterRefCmd implements Command {

	private Address fromAddr;
	private int opIndex;
	private Register reg;
	private RefType refType;
	private SourceType source;

	private String status;

	/**
	 * Constructs a new command for adding a register reference.
	 * @param fromAddr "from" address
	 * @param opIndex operand index
	 * @param reg register to add the reference to
	 * @param source the source of this reference
	 */
	public AddRegisterRefCmd(Address fromAddr, int opIndex, Register reg, SourceType source) {
		this.fromAddr = fromAddr;
		this.opIndex = opIndex;
		this.reg = reg;
		this.source = source;
	}

	/**
	 * Constructs a new command for adding a register reference.
	 * @param fromAddr "from" address
	 * @param opIndex operand index
	 * @param reg register to add the reference to
	 * @param refType reference type or null to use a default RefType
	 * @param source the source of this reference
	 */
	public AddRegisterRefCmd(Address fromAddr, int opIndex, Register reg, RefType refType,
			SourceType source) {
		this.fromAddr = fromAddr;
		this.opIndex = opIndex;
		this.reg = reg;
		this.refType = refType;
		this.source = source;
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {
		Program p = (Program) obj;
		ReferenceManager refMgr = p.getReferenceManager();

		Function f = p.getFunctionManager().getFunctionContaining(fromAddr);
		if (f == null) {
			status = "Register reference may only be created within a function";
			return false;
		}
		int useOffset = (int) (fromAddr.getOffset() - f.getEntryPoint().getOffset());

		if (refType == null) {
			refType =
				RefTypeFactory.getDefaultRegisterRefType(p.getListing().getInstructionAt(fromAddr),
					reg, opIndex);
		}

		if (refType.isWrite()) {
			boolean found = false;
			for (Variable rv : f.getAllVariables()) {
				List<Register> registers = rv.getRegisters();
				if (registers == null) {
					continue;
				}
				for (Register reg : registers) {
					if (rv.getRegister().contains(reg) && rv.getFirstUseOffset() == useOffset) {
						found = true;
						break;
					}
				}
			}
			if (!found) {
				// Create a variable on write
				try {
					Variable var =
						new LocalVariableImpl(null, useOffset, null, new VariableStorage(p, reg), p);
					var = f.addLocalVariable(var, SourceType.DEFAULT);
				}
				catch (DuplicateNameException e) {
					throw new AssertException(); // Unexpected - we did not specify name
				}
				catch (InvalidInputException e) {
					throw new AssertException(); // Unexpected - we did not specify data-type
				}
			}
		}

		refMgr.addRegisterReference(fromAddr, opIndex, reg, refType, source);

		return true;
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
		return "Add Register Reference";
	}

}
