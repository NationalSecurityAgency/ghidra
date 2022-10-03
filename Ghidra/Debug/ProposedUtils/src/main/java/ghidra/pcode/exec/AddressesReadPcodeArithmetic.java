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

import javax.help.UnsupportedOperationException;

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Endian;

/**
 * An auxilliary arithmetic that reports the union of all addresses read, typically during the
 * evaluation of an expression.
 */
public enum AddressesReadPcodeArithmetic implements PcodeArithmetic<AddressSetView> {
	/** The singleton instance */
	INSTANCE;

	@Override
	public Endian getEndian() {
		return null;
	}

	@Override
	public AddressSetView unaryOp(int opcode, int sizeout, int sizein1, AddressSetView in1) {
		return in1;
	}

	@Override
	public AddressSetView binaryOp(int opcode, int sizeout, int sizein1, AddressSetView in1,
			int sizein2, AddressSetView in2) {
		return in1.union(in2);
	}

	@Override
	public AddressSetView modBeforeStore(int sizeout, int sizeinAddress, AddressSetView inAddress,
			int sizeinValue, AddressSetView inValue) {
		return inValue;
	}

	@Override
	public AddressSetView modAfterLoad(int sizeout, int sizeinAddress, AddressSetView inAddress,
			int sizeinValue, AddressSetView inValue) {
		return inValue.union(inAddress);
	}

	@Override
	public AddressSetView fromConst(byte[] value) {
		return new AddressSet();
	}

	@Override
	public AddressSetView fromConst(BigInteger value, int size, boolean isContextreg) {
		return new AddressSet();
	}

	@Override
	public AddressSetView fromConst(BigInteger value, int size) {
		return new AddressSet();
	}

	@Override
	public AddressSetView fromConst(long value, int size) {
		return new AddressSet();
	}

	@Override
	public byte[] toConcrete(AddressSetView value, Purpose purpose) {
		throw new ConcretionError("Cannot make 'addresses read' concrete", purpose);
	}

	@Override
	public long sizeOf(AddressSetView value) {
		throw new UnsupportedOperationException();
	}
}
