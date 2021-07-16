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

import java.math.BigInteger;

import ghidra.program.model.pcode.PcodeOp;

public class OpBehaviorCountLeadingOnes extends UnaryOpBehavior {

	public OpBehaviorCountLeadingOnes() {
		super(PcodeOp.COUNTLEADINGONES);
	}

	@Override
	public long evaluateUnary(int sizeout, int sizein, long val) {
		long mask = 1L << ((sizein * 8) - 1);
		long count = 0;
		while ( (mask & val) != 0 ) {
			++count;
			val = val << 1;
		}

		return count;
	}

	@Override
	public BigInteger evaluateUnary(int sizeout, int sizein, BigInteger unsignedIn1) {
		// TODO Auto-generated method stub
		return null;
	}
}
