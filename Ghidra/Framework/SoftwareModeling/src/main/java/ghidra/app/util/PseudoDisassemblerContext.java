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
package ghidra.app.util;

import java.math.BigInteger;
import java.util.List;

import ghidra.program.disassemble.DisassemblerContextImpl;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.ProgramContext;

public class PseudoDisassemblerContext implements DisassemblerContext {

	DisassemblerContextImpl disContext;

	public PseudoDisassemblerContext(ProgramContext context) {
		this.disContext = new DisassemblerContextImpl(context);
	}

	@Override
	public Register getBaseContextRegister() {
		return disContext.getBaseContextRegister();
	}

	@Override
	public void setFutureRegisterValue(Address address, RegisterValue value) {
		disContext.setFutureRegisterValue(address, value);
	}

	@Override
	public void clearRegister(Register register) {
		disContext.clearRegister(register);
	}

	@Override
	public Register getRegister(String name) {
		return disContext.getRegister(name);
	}

	@Override
	public RegisterValue getRegisterValue(Register register) {
		return disContext.getRegisterValue(register);
	}

	@Override
	public List<Register> getRegisters() {
		return disContext.getRegisters();
	}

	@Override
	public BigInteger getValue(Register register, boolean signed) {
		return disContext.getValue(register, signed);
	}

	@Override
	public boolean hasValue(Register register) {
		return disContext.hasValue(register);
	}

	@Override
	public void setRegisterValue(RegisterValue value) {
		disContext.setRegisterValue(value);
	}

	@Override
	public void setValue(Register register, BigInteger value) {
		disContext.setValue(register, value);
	}

	public void setValue(Register register, Address addr, BigInteger value) {
		if (value == null) {
			return;
		}
		disContext.setValue(register, addr, value);
	}

	public void flowStart(Address address) {
		if (disContext.isFlowActive()) {
			disContext.flowEnd(disContext.getAddress());
		}
		disContext.flowStart(address);
	}

	public Address getAddress() {
		return disContext.getAddress();
	}

	public void flowEnd(Address address) {
		disContext.flowEnd(address);
	}

	public void flowToAddress(Address target) {
		disContext.flowToAddress(target);
	}

	public void copyToFutureFlowState(Address target) {
		disContext.copyToFutureFlowState(target);
	}

	@Override
	public void setFutureRegisterValue(Address fromAddr, Address toAddr,
			RegisterValue value) {
		disContext.setFutureRegisterValue(fromAddr, toAddr, value);
	}
}
