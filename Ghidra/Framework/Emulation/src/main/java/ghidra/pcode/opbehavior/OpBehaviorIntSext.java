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

public class OpBehaviorIntSext extends UnaryOpBehavior {

	public OpBehaviorIntSext() {
		super(PcodeOp.INT_SEXT);
	}

	@Override
	public long evaluateUnary(int sizeout, int sizein, long in1) {
		long res = Utils.sign_extend(in1, sizein, sizeout);
		return res;
	}

	@Override
	public BigInteger evaluateUnary(int sizeout, int sizein, BigInteger in1) {
		return Utils.convertToSignedValue(in1, sizein);
	}

//    @Override
//    public long recoverInputUnary(int sizeout, long out, int sizein) {
//        long masklong = Utils.calc_mask(sizeout);
//        long maskshort = Utils.calc_mask(sizein);
//
//        if ((out & (maskshort ^ (maskshort >>> 1))) == 0) { // Positive input
//            if ((out & maskshort) != out)
//                throw new LowlevelError(
//                        "Output is not in range of sext operation");
//        } else { // Negative input
//            if ((out & (masklong ^ maskshort)) != (masklong ^ maskshort))
//                throw new LowlevelError(
//                        "Output is not in range of sext operation");
//        }
//        return (out & maskshort);
//    }
}
