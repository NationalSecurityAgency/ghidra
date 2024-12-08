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

import java.math.BigInteger;

public class OpBehaviorIntLessEqual extends BinaryOpBehavior {

	public OpBehaviorIntLessEqual() {
		super(PcodeOp.INT_LESSEQUAL);
	}

	@Override
	public long evaluateBinary(int sizeout, int sizein, long in1, long in2) {
		long res, mask, bit1, bit2;
		if (sizein <= 0) {
			res = 0;
		}
		else {
			mask = Utils.calc_mask(sizein);
			in1 &= mask;
			in2 &= mask;
			if (in1 == in2) {
				res = 1;
			}
			else if (sizein < 8) {
				res = (in1 < in2) ? 1 : 0;
			}
			else {
				mask = 0x80;
				mask <<= 8 * (sizein - 1);
				bit1 = in1 & mask; // Get the sign bits
				bit2 = in2 & mask;
				if (bit1 != bit2)
					res = (bit1 != 0) ? 0 : 1;
				else
					res = (in1 < in2) ? 1 : 0;
			}
		}
		return res;
	}

	@Override
	public BigInteger evaluateBinary(int sizeout, int sizein, BigInteger in1, BigInteger in2) {
		BigInteger res = (in1.compareTo(in2) <= 0) ? BigInteger.ONE : BigInteger.ZERO;
		return res;
	}

}
