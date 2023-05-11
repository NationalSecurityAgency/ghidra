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

import ghidra.pcode.floatformat.FloatFormat;
import ghidra.pcode.floatformat.FloatFormatFactory;
import ghidra.program.model.pcode.PcodeOp;

import java.math.BigInteger;

public class OpBehaviorFloatTrunc extends UnaryOpBehavior {

	public OpBehaviorFloatTrunc() {
		super(PcodeOp.FLOAT_TRUNC);
	}

	@Override
	public long evaluateUnary(int sizeout, int sizein, long in1) {
		FloatFormat format = FloatFormatFactory.getFloatFormat(sizein);
		return format.opTrunc(in1, sizeout);
	}

	@Override
	public BigInteger evaluateUnary(int sizeout, int sizein, BigInteger in1) {
		FloatFormat format = FloatFormatFactory.getFloatFormat(sizein);
		return format.opTrunc(in1, sizeout);
	}
}
