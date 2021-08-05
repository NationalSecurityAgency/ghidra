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
import ghidra.pcode.utils.Utils;
import ghidra.program.model.lang.Language;

public enum BytesPcodeArithmetic implements PcodeArithmetic<byte[]> {
	BIG_ENDIAN(true), LITTLE_ENDIAN(false);

	public static BytesPcodeArithmetic forEndian(boolean bigEndian) {
		return bigEndian ? BIG_ENDIAN : LITTLE_ENDIAN;
	}

	public static BytesPcodeArithmetic forLanguage(Language language) {
		return forEndian(language.isBigEndian());
	}

	private final boolean isBigEndian;

	private BytesPcodeArithmetic(boolean isBigEndian) {
		this.isBigEndian = isBigEndian;
	}

	@Override
	public byte[] unaryOp(UnaryOpBehavior op, int sizeout, int sizein1, byte[] in1) {
		if (sizein1 > 8 || sizeout > 8) {
			BigInteger in1Val = Utils.bytesToBigInteger(in1, in1.length, isBigEndian, false);
			BigInteger outVal = op.evaluateUnary(sizeout, sizein1, in1Val);
			return Utils.bigIntegerToBytes(outVal, sizeout, isBigEndian);
		}
		else {
			long in1Val = Utils.bytesToLong(in1, sizein1, isBigEndian);
			long outVal = op.evaluateUnary(sizeout, sizein1, in1Val);
			return Utils.longToBytes(outVal, sizeout, isBigEndian);
		}
	}

	@Override
	public byte[] binaryOp(BinaryOpBehavior op, int sizeout, int sizein1, byte[] in1, int sizein2,
			byte[] in2) {
		if (sizein1 > 8 || sizein2 > 8 || sizeout > 8) {
			BigInteger in1Val = Utils.bytesToBigInteger(in1, sizein1, isBigEndian, false);
			BigInteger in2Val = Utils.bytesToBigInteger(in2, sizein2, isBigEndian, false);
			BigInteger outVal = op.evaluateBinary(sizeout, sizein1, in1Val, in2Val);
			return Utils.bigIntegerToBytes(outVal, sizeout, isBigEndian);
		}
		else {
			long in1Val = Utils.bytesToLong(in1, sizein1, isBigEndian);
			long in2Val = Utils.bytesToLong(in2, sizein2, isBigEndian);
			long outVal = op.evaluateBinary(sizeout, sizein1, in1Val, in2Val);
			return Utils.longToBytes(outVal, sizeout, isBigEndian);
		}
	}

	@Override
	public byte[] fromConst(long value, int size) {
		return Utils.longToBytes(value, size, isBigEndian);
	}

	@Override
	public byte[] fromConst(BigInteger value, int size) {
		return Utils.bigIntegerToBytes(value, size, isBigEndian);
	}

	@Override
	public boolean isTrue(byte[] cond) {
		for (byte b : cond) {
			if (b != 0) {
				return true;
			}
		}
		return false;
	}

	@Override
	public BigInteger toConcrete(byte[] value) {
		return Utils.bytesToBigInteger(value, value.length, isBigEndian, false);
	}
}
