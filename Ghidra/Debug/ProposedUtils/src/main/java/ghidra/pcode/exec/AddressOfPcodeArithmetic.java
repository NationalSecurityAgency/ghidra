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
package ghidra.pcode.exec;

import java.math.BigInteger;

import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.program.model.address.Address;

/**
 * A rider arithmetic that reports the address of the control value
 * 
 * <p>
 * This is intended for use as the right side of a {@link PairedPcodeArithmetic}. Note that constant
 * and unique spaces are never returned. Furthermore, any computation performed on a value,
 * producing a temporary value, philosophically does not exist at any address in the state. Thus,
 * every operation in this arithmetic results in {@code null}. The accompanying state
 * {@link AddressOfPcodeExecutorState} does the real "address of" logic.
 */
public enum AddressOfPcodeArithmetic implements PcodeArithmetic<Address> {
	// NB: No temp value has a real address
	/**
	 * The singleton instance.
	 */
	INSTANCE;

	@Override
	public Address unaryOp(UnaryOpBehavior op, int sizeout, int sizein1, Address in1) {
		return null;
	}

	@Override
	public Address binaryOp(BinaryOpBehavior op, int sizeout, int sizein1, Address in1, int sizein2,
			Address in2) {
		return null;
	}

	@Override
	public Address fromConst(long value, int size) {
		return null; // TODO: Do we care about Constant space?
	}

	@Override
	public Address fromConst(BigInteger value, int size, boolean isContextreg) {
		return null;
	}

	@Override
	public boolean isTrue(Address cond) {
		throw new AssertionError("Cannot decide branches using 'address of'");
	}

	@Override
	public BigInteger toConcrete(Address value, boolean isContextreg) {
		throw new AssertionError("Should not attempt to concretize 'address of'");
	}

	@Override
	public Address sizeOf(Address value) {
		return fromConst(value.getAddressSpace().getSize() / 8, SIZEOF_SIZEOF);
	}
}
