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

import ghidra.pcode.opbehavior.*;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.lang.Language;

/**
 * A p-code arithmetic that operates on concrete byte array values
 * 
 * <p>
 * The arithmetic interprets the arrays as big- or little-endian values, then performs the
 * arithmetic as specified by the p-code operation. The implementation defers to {@link OpBehavior}.
 */
public enum BytesPcodeArithmetic implements PcodeArithmetic<byte[]> {
	/**
	 * The instance which interprets arrays as big-endian values
	 */
	BIG_ENDIAN(Endian.BIG),
	/**
	 * The instance which interprets arrays as little-endian values
	 */
	LITTLE_ENDIAN(Endian.LITTLE);

	/**
	 * Obtain the instance for the given endianness
	 * 
	 * @param bigEndian true for {@link #BIG_ENDIAN}, false of {@link #LITTLE_ENDIAN}
	 * @return the arithmetic
	 */
	public static BytesPcodeArithmetic forEndian(boolean bigEndian) {
		return bigEndian ? BIG_ENDIAN : LITTLE_ENDIAN;
	}

	/**
	 * Obtain the instance for the given language's endianness
	 * 
	 * @param language the language
	 * @return the arithmetic
	 */
	public static BytesPcodeArithmetic forLanguage(Language language) {
		return forEndian(language.isBigEndian());
	}

	private final Endian endian;

	private BytesPcodeArithmetic(Endian endian) {
		this.endian = endian;
	}

	@Override
	public Endian getEndian() {
		return endian;
	}

	@Override
	public byte[] unaryOp(int opcode, int sizeout, int sizein1, byte[] in1) {
		UnaryOpBehavior b = (UnaryOpBehavior) OpBehaviorFactory.getOpBehavior(opcode);
		boolean isBigEndian = endian.isBigEndian();
		if (sizein1 > 8 || sizeout > 8) {
			BigInteger in1Val = Utils.bytesToBigInteger(in1, sizein1, isBigEndian, false);
			BigInteger outVal = b.evaluateUnary(sizeout, sizein1, in1Val);
			return Utils.bigIntegerToBytes(outVal, sizeout, isBigEndian);
		}
		long in1Val = Utils.bytesToLong(in1, sizein1, isBigEndian);
		long outVal = b.evaluateUnary(sizeout, sizein1, in1Val);
		return Utils.longToBytes(outVal, sizeout, isBigEndian);
	}

	@Override
	public byte[] binaryOp(int opcode, int sizeout, int sizein1, byte[] in1, int sizein2,
			byte[] in2) {
		BinaryOpBehavior b = (BinaryOpBehavior) OpBehaviorFactory.getOpBehavior(opcode);
		boolean isBigEndian = endian.isBigEndian();
		if (sizein1 > 8 || sizein2 > 8 || sizeout > 8) {
			BigInteger in1Val = Utils.bytesToBigInteger(in1, sizein1, isBigEndian, false);
			BigInteger in2Val = Utils.bytesToBigInteger(in2, sizein2, isBigEndian, false);
			BigInteger outVal = b.evaluateBinary(sizeout, sizein1, in1Val, in2Val);
			return Utils.bigIntegerToBytes(outVal, sizeout, isBigEndian);
		}
		long in1Val = Utils.bytesToLong(in1, sizein1, isBigEndian);
		long in2Val = Utils.bytesToLong(in2, sizein2, isBigEndian);
		long outVal = b.evaluateBinary(sizeout, sizein1, in1Val, in2Val);
		return Utils.longToBytes(outVal, sizeout, isBigEndian);
	}

	@Override
	public byte[] modBeforeStore(int sizeout, int sizeinAddress, byte[] inAddress, int sizeinValue,
			byte[] inValue) {
		return inValue;
	}

	@Override
	public byte[] modAfterLoad(int sizeout, int sizeinAddress, byte[] inAddress, int sizeinValue,
			byte[] inValue) {
		return inValue;
	}

	@Override
	public byte[] fromConst(byte[] value) {
		return value;
	}

	@Override
	public byte[] toConcrete(byte[] value, Purpose purpose) {
		return value;
	}

	@Override
	public long sizeOf(byte[] value) {
		return value.length;
	}
}
