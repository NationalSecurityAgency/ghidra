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
package ghidra.app.cmd.register;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;

import java.math.BigInteger;

/**
 * Command for setting the value of a register over a range of addresses.
 */
public class SetRegisterCmd implements Command {
	private Register register;
	private Address start;
	private Address end;
	private BigInteger value;
	private String errorMsg;

	/**
	 * Constructor for SetRegisterCmd.
	 * @param register      the register to change.
	 * @param start         the starting address of the range.
	 * @param end           the ending address of the range.
	 * @param value         the value to associated over the range.
	 *                      A null value indicates that no value should be associated over the range.
	 */
	public SetRegisterCmd(Register register, Address start, Address end, BigInteger value) {
		if (start.getAddressSpace() != end.getAddressSpace()) {
			throw new IllegalArgumentException(
				"start and end address must be in the same address space");
		}

		this.register = register;
		this.start = start;
		this.end = end;
		this.value = value;
	}

	/**
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {
		Program program = (Program) obj;
		ProgramContext context = program.getProgramContext();

		try {
			context.setValue(register, start, end, value);
		}
		catch (ContextChangeException e) {
			errorMsg = e.getMessage();
			Msg.error(this, e.getMessage());
			return false;
		}
		return true;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return errorMsg;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return "Set Register Value";
	}

}
