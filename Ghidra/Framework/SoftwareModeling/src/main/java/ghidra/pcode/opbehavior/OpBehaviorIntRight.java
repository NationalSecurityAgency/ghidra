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

public class OpBehaviorIntRight extends BinaryOpBehavior {

	public OpBehaviorIntRight() {
		super(PcodeOp.INT_RIGHT);
	}

	@Override
	public long evaluateBinary(int sizeout, int sizein, long in1, long in2) {
		if (in2 < 0 || in2 >= (8 * sizein)) {
			return 0;
		}
		return (in1 >>> in2) & Utils.calc_mask(sizeout);
	}

	@Override
	public BigInteger evaluateBinary(int sizeout, int sizein, BigInteger in1, BigInteger in2) {

		if (in1.signum() < 0 || in2.signum() < 0) {
			throw new AssertException("Expected unsigned in values");
		}
		BigInteger maxShift = BigInteger.valueOf(sizein * 8);
		if (in2.compareTo(maxShift) >= 0) {
			return BigInteger.ZERO;
		}
		return in1.shiftRight(in2.intValue());
	}

}
