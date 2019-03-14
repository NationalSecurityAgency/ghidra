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

import ghidra.program.model.pcode.PcodeOp;

import java.math.BigInteger;

public class OpBehaviorIntScarry extends BinaryOpBehavior {

	public OpBehaviorIntScarry() {
		super(PcodeOp.INT_SCARRY);
	}

	@Override
	public long evaluateBinary(int sizeout, int sizein, long in1, long in2) {
		long res = in1 + in2;

		int a = (int) (in1 >> (sizein * 8 - 1)) & 1; // Grab sign bit
		int b = (int) (in2 >> (sizein * 8 - 1)) & 1; // Grab sign bit
		int r = (int) (res >> (sizein * 8 - 1)) & 1; // Grab sign bit

		r ^= a;
		a ^= b;
		a ^= 1;
		r &= a;
		return r;
	}

	@Override
	public BigInteger evaluateBinary(int sizeout, int sizein, BigInteger in1, BigInteger in2) {
		BigInteger res = in1.add(in2);

		boolean a = in1.testBit(sizein * 8 - 1); // Grab sign bit
		boolean b = in2.testBit(sizein * 8 - 1); // Grab sign bit
		boolean r = res.testBit(sizein * 8 - 1); // Grab sign bit

		r ^= a;
		a ^= b;
		a ^= true;
		r &= a;
		return r ? BigInteger.ONE : BigInteger.ZERO;
	}

}
