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
package ghidra.pcode.opbehavior;

import ghidra.pcode.utils.Utils;
import ghidra.program.model.pcode.PcodeOp;

import java.math.BigInteger;

public class OpBehaviorIntDiv extends BinaryOpBehavior {

	public OpBehaviorIntDiv() {
		super(PcodeOp.INT_DIV);
	}

	@Override
	public long evaluateBinary(int sizeout, int sizein, long in1, long in2) {
		if (sizein <= 0 || in2 == 0)
			return 0;
		if (in1 == in2)
			return 1;
		if (sizein == 8) {
			long mask = (0x1<<63);
			long bit1 = in1 & mask; // Get the sign bits
			long bit2 = in2 & mask;
			if (bit1 != 0 || bit2 != 0) {
				// use BigInteger to perform 64-bit unsigned division if one negative input
				BigInteger bigIn1 =
					Utils.bytesToBigInteger(Utils.longToBytes(in1, sizein, true), sizein, true,
						false);
				if (bigIn1.signum() < 0) {
					bigIn1 = Utils.convertToUnsignedValue(bigIn1, sizein);
				}
				BigInteger bigIn2 =
					Utils.bytesToBigInteger(Utils.longToBytes(in2, sizein, true), sizein, true,
						false);
				if (bigIn2.signum() < 0) {
					bigIn2 = Utils.convertToUnsignedValue(bigIn2, sizein);
				}
				BigInteger result = bigIn1.divide(bigIn2);
				return result.longValue() & Utils.calc_mask(sizeout);
			}
		}

		return (in1 / in2) & Utils.calc_mask(sizeout);
	}

	@Override
	public BigInteger evaluateBinary(int sizeout, int sizein, BigInteger in1, BigInteger in2) {
		if (sizein <= 0 || in2.signum() == 0)
			return BigInteger.ZERO;
		BigInteger res = in1.divide(in2);
		return res;
	}

}
