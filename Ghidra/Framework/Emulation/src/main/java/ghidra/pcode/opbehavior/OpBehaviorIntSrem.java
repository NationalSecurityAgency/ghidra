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

import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.pcode.PcodeOp;

import java.math.BigInteger;

public class OpBehaviorIntSrem extends BinaryOpBehavior {

	public OpBehaviorIntSrem() {
		super(PcodeOp.INT_SREM);
	}

	@Override
	public long evaluateBinary(int sizeout, int sizein, long in1, long in2) {
		if (in2 == 0)
			throw new LowlevelError("Remainder by 0");
		long val = in1;
		long mod = in2;
		// Convert inputs to signed values
		val = Utils.zzz_sign_extend(val, 8 * sizein - 1);
		mod = Utils.zzz_sign_extend(mod, 8 * sizein - 1);
		// Do the remainder
		long sres = val % mod;
		// Convert back to unsigned
		sres = Utils.zzz_zero_extend(sres, 8 * sizeout - 1);
		return sres;
	}

	@Override
	public BigInteger evaluateBinary(int sizeout, int sizein, BigInteger in1, BigInteger in2) {
		if (in2.signum() == 0)
			throw new LowlevelError("Remainder by 0");
		// convert to signed
		in1 = Utils.convertToSignedValue(in1, sizein);
		in2 = Utils.convertToSignedValue(in2, sizein);
		return in1.remainder(in2);
	}

}
