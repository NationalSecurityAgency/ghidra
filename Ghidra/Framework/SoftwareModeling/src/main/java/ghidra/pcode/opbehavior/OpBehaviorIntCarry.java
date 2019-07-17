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

public class OpBehaviorIntCarry extends BinaryOpBehavior {

	public OpBehaviorIntCarry() {
		super(PcodeOp.INT_CARRY);
	}

	@Override
	public long evaluateBinary(int sizeout, int sizein, long in1, long in2) {
		// must handle possible 64-bit signed case special
		if (sizein == 8) {
			if (in1 < 0) {
				return ((in2 < 0) || (-in2 <= in1)) ? 1 : 0;
			}
			if (in2 < 0) {
				return (-in1 <= in2) ? 1 : 0;
			}
		}
		return (in1 > ((in1 + in2) & Utils.calc_mask(sizein))) ? 1 : 0;
	}

	@Override
	public BigInteger evaluateBinary(int sizeout, int sizein, BigInteger in1, BigInteger in2) {
		if (in1.signum() < 0 || in2.signum() < 0) {
			throw new AssertException("Expected unsigned in values");
		}
		BigInteger res =
			(in1.compareTo(in1.add(in2).and(Utils.calc_bigmask(sizein))) > 0) ? BigInteger.ONE
					: BigInteger.ZERO;
		return res;
	}

}
