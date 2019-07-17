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
package ghidra.pcodeCPort.slghpatexpress;

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.context.ParserWalker;
import ghidra.pcodeCPort.utils.Utils;

public class ExpressUtils {

	// Build a long from the instruction bytes
	static long getInstructionBytes(ParserWalker pos, int bytestart, int byteend, boolean bigendian) {
		long res = 0;

		int size = byteend - bytestart + 1;
		int tmpsize = size;
		while (tmpsize >= 4) {
			int tmp = pos.getInstructionBytes(bytestart, 4);
			res <<= 32;
			res |= tmp;
			bytestart += 4;
			tmpsize -= 4;
		}
		if (tmpsize > 0) {
			int tmp = pos.getInstructionBytes(bytestart, tmpsize);
			res <<= 8 * tmpsize;
			res |= tmp;
		}
		if (!bigendian) {
			res = Utils.byte_swap(res, size);
		}
		return res;
	}

	// Build a intb from the context bytes
	static long getContextBytes(ParserWalker pos, int bytestart, int byteend) {
		long res = 0;

		int size = byteend - bytestart + 1;
		while (size >= 4) {
			int tmp = pos.getContextBytes(bytestart, 4);
			res <<= 32;
			res |= tmp;
			bytestart += 4;
			size = byteend - bytestart + 1;
		}
		if (size > 0) {
			int tmp = pos.getContextBytes(bytestart, size);
			res <<= 8 * size;
			res |= tmp;
		}
		return res;
	}

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
