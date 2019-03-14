/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
import ghidra.util.exception.AssertException;

import java.math.BigInteger;

public class OpBehaviorIntSright extends BinaryOpBehavior {

	public OpBehaviorIntSright() {
		super(PcodeOp.INT_SRIGHT);
	}

	@Override
	public long evaluateBinary(int sizeout, int sizein, long in1, long in2) {
		long maxShift = (sizein * 8) - 1;
		if (in2 < 0 || in2 > maxShift) {
			if (Utils.signbit_negative(in1, sizein)) {
				return Utils.calc_mask(sizein);
			}
			return 0;
		}
		long res;
		if (Utils.signbit_negative(in1, sizein)) {
			res = in1 >> in2;
			long mask = Utils.calc_mask(sizein);
			mask = (mask >>> in2) ^ mask;
			res |= mask;
		}
		else {
			res = in1 >>> in2;
		}
		return res;
	}

	@Override
	public BigInteger evaluateBinary(int sizeout, int sizein, BigInteger in1, BigInteger in2) {
		if (in1.signum() < 0 || in2.signum() < 0) {
			throw new AssertException("Expected unsigned in values");
		}
		int signbit = (sizein * 8) - 1;
		BigInteger maxShift = BigInteger.valueOf(signbit);
		if (in2.compareTo(maxShift) > 0) {
			in2 = maxShift;
		}
		if (in1.testBit(signbit)) {
			in1 = Utils.convertToSignedValue(in1, sizein);
		}
		return in1.shiftRight(in2.intValue());
	}

}
