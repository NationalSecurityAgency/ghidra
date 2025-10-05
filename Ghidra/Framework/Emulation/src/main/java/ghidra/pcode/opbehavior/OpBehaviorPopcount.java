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

public class OpBehaviorPopcount extends UnaryOpBehavior {

	public OpBehaviorPopcount() {
		super(PcodeOp.POPCOUNT);
	}

	@Override
	public long evaluateUnary(int sizeout, int sizein, long val) {
		return Long.bitCount(val);
	}

	@Override
	public BigInteger evaluateUnary(int sizeout, int sizein, BigInteger unsignedIn1) {
		return BigInteger.valueOf(unsignedIn1.bitCount());
	}

}
