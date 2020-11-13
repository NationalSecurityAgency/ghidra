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
		val = (val & 0x5555555555555555L) + ((val >>> 1) & 0x5555555555555555L);
		val = (val & 0x3333333333333333L) + ((val >>> 2) & 0x3333333333333333L);
		val = (val & 0x0f0f0f0f0f0f0f0fL) + ((val >>> 4) & 0x0f0f0f0f0f0f0f0fL);
		val = (val & 0x00ff00ff00ff00ffL) + ((val >>> 8) & 0x00ff00ff00ff00ffL);
		val = (val & 0x0000ffff0000ffffL) + ((val >>> 16) & 0x0000ffff0000ffffL);
		int res = (int) (val & 0xff);
		res += (int) ((val >> 32) & 0xff);
		return res;
	}

	@Override
	public BigInteger evaluateUnary(int sizeout, int sizein, BigInteger unsignedIn1) {
		// TODO Auto-generated method stub
		return null;
	}

}
