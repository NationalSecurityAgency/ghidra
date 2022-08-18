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
package ghidra.pcodeCPort.slghpatexpress;

import generic.stl.VectorSTL;

public class ExpressUtils {

	static boolean advance_combo(VectorSTL<Long> val, VectorSTL<Long> min, VectorSTL<Long> max) {
		int i = 0;
		while (i < val.size()) {
			val.set(i, val.get(i).longValue() + 1);
			if (val.get(i).longValue() <= max.get(i).longValue()) { // maximum is inclusive
				return true;
			}
			val.set(i, min.get(i));
			i += 1;
		}
		return false;
	}

	static TokenPattern buildPattern(PatternValue lhs, long lhsval, VectorSTL<PatternValue> semval,
			VectorSTL<Long> val) {
		TokenPattern respattern = lhs.genPattern(lhsval);

		for (int i = 0; i < semval.size(); ++i) {
			respattern.copyInto(respattern.doAnd(semval.get(i).genPattern(val.get(i))));
		}
		return respattern;
	}

}
