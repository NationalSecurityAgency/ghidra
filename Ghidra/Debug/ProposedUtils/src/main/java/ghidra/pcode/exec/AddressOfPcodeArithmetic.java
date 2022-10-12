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

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Endian;

/**
 * An auxiliary arithmetic that reports the address of the control value
 * 
 * <p>
 * This is intended for use as the right side of a {@link PairedPcodeArithmetic}. Note that constant
 * and unique spaces are never returned. Furthermore, any computation performed on a value,
 * producing a temporary value, philosophically does not exist at any address in the state. Thus,
 * every operation in this arithmetic results in {@code null}. The accompanying state piece
 * {@link AddressOfPcodeExecutorStatePiece} does the real "address of" logic.
 */
public enum AddressOfPcodeArithmetic implements PcodeArithmetic<Address> {
	// NB: No temp value has a real address
	/** The singleton instance */
	INSTANCE;

	@Override
	public Endian getEndian() {
		return null;
	}

	@Override
	public Address unaryOp(int opcode, int sizeout, int sizein1, Address in1) {
		return null;
	}

	@Override
	public Address binaryOp(int opcode, int sizeout, int sizein1, Address in1, int sizein2,
			Address in2) {
		return null;
	}

	@Override
	public Address modBeforeStore(int sizeout, int sizeinAddress, Address inAddress,
			int sizeinValue, Address inValue) {
		return inValue;
	}

	@Override
	public Address modAfterLoad(int sizeout, int sizeinAddress, Address inAddress, int sizeinValue,
			Address inValue) {
		return inValue;
	}

	@Override
	public Address fromConst(byte[] value) {
		return null; // TODO: Do we care about constant space?
	}

	@Override
	public Address fromConst(BigInteger value, int size, boolean isContextreg) {
		return null;
	}

	@Override
	public Address fromConst(BigInteger value, int size) {
		return null;
	}

	@Override
	public Address fromConst(long value, int size) {
		return null;
	}

	@Override
	public byte[] toConcrete(Address value, Purpose purpose) {
		throw new ConcretionError("Cannot make 'address of' concrete", purpose);
	}

	@Override
	public long sizeOf(Address value) {
		return value.getAddressSpace().getSize() / 8;
	}
}
