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

public enum BigIntegerPcodeArithmetic implements PcodeArithmetic<BigInteger> {
	INSTANCE;

	@Override
	public BigInteger unaryOp(UnaryOpBehavior op, int sizeout, int sizein1, BigInteger in1) {
		return op.evaluateUnary(sizeout, sizein1, in1);
	}

	@Override
	public BigInteger binaryOp(BinaryOpBehavior op, int sizeout, int sizein1, BigInteger in1,
			int sizein2, BigInteger in2) {
		return op.evaluateBinary(sizeout, sizein1, in1, in2);
	}

	@Override
	public BigInteger fromConst(long value, int size) {
		return BigInteger.valueOf(value);
	}

	@Override
	public BigInteger fromConst(BigInteger value, int size) {
		return value;
	}

	@Override
	public boolean isTrue(BigInteger cond) {
		return !cond.equals(BigInteger.ZERO);
	}

	@Override
	public BigInteger toConcrete(BigInteger value) {
		return value;
	}
}
