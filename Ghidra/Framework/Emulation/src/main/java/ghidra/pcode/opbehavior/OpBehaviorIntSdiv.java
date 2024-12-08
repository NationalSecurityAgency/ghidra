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

public class OpBehaviorIntSdiv extends BinaryOpBehavior {

	public OpBehaviorIntSdiv() {
		super(PcodeOp.INT_SDIV);
	}

	@Override
	public long evaluateBinary(int sizeout, int sizein, long in1, long in2) {
		if (in2 == 0)
			throw new LowlevelError("Divide by 0");
		long num = in1; // Convert to signed
		long denom = in2;
		num = Utils.zzz_sign_extend(num, 8 * sizein - 1);
		denom = Utils.zzz_sign_extend(denom, 8 * sizein - 1);
		long sres = num / denom; // Do the signed division
		// Cut to appropriate size
		sres = Utils.zzz_zero_extend(sres, 8 * sizeout - 1);
		return sres; // Recast as unsigned
	}

	@Override
	public BigInteger evaluateBinary(int sizeout, int sizein, BigInteger in1, BigInteger in2) {
		if (in2.signum() == 0)
			throw new LowlevelError("Divide by 0");
		// convert to signed
		in1 = Utils.convertToSignedValue(in1, sizein);
		in2 = Utils.convertToSignedValue(in2, sizein);
		return in1.divide(in2);
	}

}
