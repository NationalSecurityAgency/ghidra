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
package ghidra.pcode.emu;

import java.math.BigInteger;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.ContextChangeException;

public interface DisassemblerContextAdapter extends DisassemblerContext {
	@Override
	default Register getBaseContextRegister() {
		throw new UnsupportedOperationException();
	}

	@Override
	default List<Register> getRegisters() {
		throw new UnsupportedOperationException();
	}

	@Override
	default Register getRegister(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	default BigInteger getValue(Register register, boolean signed) {
		throw new UnsupportedOperationException();
	}

	@Override
	default RegisterValue getRegisterValue(Register register) {
		throw new UnsupportedOperationException();
	}

	@Override
	default boolean hasValue(Register register) {
		throw new UnsupportedOperationException();
	}

	@Override
	default void setValue(Register register, BigInteger value)
			throws ContextChangeException {
		throw new UnsupportedOperationException();
	}

	@Override
	default void setRegisterValue(RegisterValue value) throws ContextChangeException {
		throw new UnsupportedOperationException();
	}

	@Override
	default void clearRegister(Register register) throws ContextChangeException {
		throw new UnsupportedOperationException();
	}

	@Override
	default void setFutureRegisterValue(Address address, RegisterValue value) {
		throw new UnsupportedOperationException();
	}

	@Override
	default void setFutureRegisterValue(Address fromAddr, Address toAddr,
			RegisterValue value) {
		throw new UnsupportedOperationException();
	}
}
