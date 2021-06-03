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
package ghidra.program.model.lang;

import java.math.BigInteger;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.ProgramContext;

/**
 * Implementation for the program processor context interface
 */
public class ProgramProcessorContext implements ProcessorContext {
	private Address addr;
	private ProgramContext context;

	/**
	 * Constructs a new ProgramProcessorContext that will have the processor
	 * state be the state of the given programContext at the given address
	 * @param context the programContext which contains the register state at every address
	 * @param addr the address at which to get the register state
	 */
	public ProgramProcessorContext(ProgramContext context, Address addr) {
		this.context = context;
		this.addr = addr;
	}

	@Override
	public Register getBaseContextRegister() {
		return context.getBaseContextRegister();
	}

	@Override
	public List<Register> getRegisters() {
		return context.getRegisters();
	}

	@Override
	public Register getRegister(String name) {
		return context.getRegister(name);
	}

	@Override
	public BigInteger getValue(Register register, boolean signed) {
		return context.getValue(register, addr, signed);
	}

	@Override
	public RegisterValue getRegisterValue(Register register) {
		return context.getRegisterValue(register, addr);
	}

	@Override
	public void setValue(Register register, BigInteger value) throws ContextChangeException {
		context.setValue(register, addr, addr, value);
	}

	@Override
	public void setRegisterValue(RegisterValue value) throws ContextChangeException {
		context.setRegisterValue(addr, addr, value);
	}

	@Override
	public void clearRegister(Register register) throws ContextChangeException {
		context.remove(addr, addr, register);
	}

	/**
	 * @see ghidra.program.model.lang.ProcessorContext#hasValue(ghidra.program.model.lang.Register)
	 */
	@Override
	public boolean hasValue(Register register) {
		return context.getValue(register, addr, true) != null;
	}

}
