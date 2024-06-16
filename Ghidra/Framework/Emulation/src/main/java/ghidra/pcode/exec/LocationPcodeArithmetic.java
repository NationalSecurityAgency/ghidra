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

import ghidra.pcode.utils.Utils;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.pcode.PcodeOp;

/**
 * An auxiliary arithmetic that reports the location the control value
 * 
 * <p>
 * This is intended for use as the right side of a {@link PairedPcodeArithmetic}. Note that constant
 * and unique spaces are never returned. Furthermore, any computation performed on a value,
 * producing a temporary value, philosophically does not exist at any location in the state. Thus,
 * most operations in this arithmetic result in {@code null}. The accompanying state piece
 * {@link LocationPcodeExecutorStatePiece} generates the actual locations.
 */
public enum LocationPcodeArithmetic implements PcodeArithmetic<ValueLocation> {
	BIG_ENDIAN(Endian.BIG), LITTLE_ENDIAN(Endian.LITTLE);

	public static LocationPcodeArithmetic forEndian(boolean bigEndian) {
		return bigEndian ? BIG_ENDIAN : LITTLE_ENDIAN;
	}

	private final Endian endian;

	private LocationPcodeArithmetic(Endian endian) {
		this.endian = endian;
	}

	@Override
	public Endian getEndian() {
		return endian;
	}

	@Override
	public ValueLocation unaryOp(int opcode, int sizeout, int sizein1, ValueLocation in1) {
		switch (opcode) {
			case PcodeOp.COPY:
			case PcodeOp.INT_ZEXT:
			case PcodeOp.INT_SEXT:
				return in1;
			default:
				return null;
		}
	}

	@Override
	public ValueLocation binaryOp(int opcode, int sizeout, int sizein1, ValueLocation in1,
			int sizein2, ValueLocation in2) {
		switch (opcode) {
			case PcodeOp.INT_LEFT:
				BigInteger amount = in2 == null ? null : in2.getConst();
				if (in2 == null) {
					return null;
				}
				return in1.shiftLeft(amount.intValue());
			case PcodeOp.INT_OR:
				return in1 == null || in2 == null ? null : in1.intOr(in2);
			default:
				return null;
		}
	}

	@Override
	public ValueLocation modBeforeStore(int sizeout, int sizeinAddress, ValueLocation inAddress,
			int sizeinValue, ValueLocation inValue) {
		return inValue;
	}

	@Override
	public ValueLocation modAfterLoad(int sizeout, int sizeinAddress, ValueLocation inAddress,
			int sizeinValue, ValueLocation inValue) {
		return inValue;
	}

	@Override
	public ValueLocation fromConst(byte[] value) {
		return ValueLocation.fromConst(Utils.bytesToLong(value, value.length, endian.isBigEndian()),
			value.length);
	}

	@Override
	public ValueLocation fromConst(BigInteger value, int size, boolean isContextreg) {
		return ValueLocation.fromConst(value.longValueExact(), size);
	}

	@Override
	public ValueLocation fromConst(BigInteger value, int size) {
		return ValueLocation.fromConst(value.longValueExact(), size);
	}

	@Override
	public ValueLocation fromConst(long value, int size) {
		return ValueLocation.fromConst(value, size);
	}

	@Override
	public byte[] toConcrete(ValueLocation value, Purpose purpose) {
		throw new ConcretionError("Cannot make 'location' concrete", purpose);
	}

	@Override
	public long sizeOf(ValueLocation value) {
		return value == null ? 0 : value.size();
	}
}
