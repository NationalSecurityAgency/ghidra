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
import ghidra.pcodeCPort.slghsymbol.Constructor;
import ghidra.pcodeCPort.slghsymbol.OperandSymbol;
import ghidra.sleigh.grammar.Location;

// Pattern Equations concatenated
public class EquationCat extends PatternEquation {

	private PatternEquation left;
	private PatternEquation right;

	public EquationCat(Location location, PatternEquation l, PatternEquation r) {
		super(location);
		(left = l).layClaim();
		(right = r).layClaim();
	}

	@Override
	public void dispose() {
		super.release(left);
		super.release(right);
	}

	@Override
	public void genPattern(VectorSTL<TokenPattern> ops) {
		left.genPattern(ops);
		right.genPattern(ops);
		setTokenPattern(left.getTokenPattern().doCat(right.getTokenPattern()));
	}

	@Override
	public void operandOrder(Constructor ct, VectorSTL<OperandSymbol> order) {
		left.operandOrder(ct, order); // List operands left
		right.operandOrder(ct, order); //  to right
	}

	@Override
	public boolean resolveOperandLeft(OperandResolve state) {
		boolean res = left.resolveOperandLeft(state);
		if (!res) return false;
		int cur_base = state.base;
		int cur_offset = state.offset;
		if ((!left.getTokenPattern().getLeftEllipsis())&&(!left.getTokenPattern().getRightEllipsis())) {
			// Keep the same base
			state.offset += left.getTokenPattern().getMinimumLength();	// But add to its size
		}
		else if (state.cur_rightmost != -1) {
			state.base = state.cur_rightmost;
			state.offset = state.size;
		}
		else if (state.size != -1) {
			state.offset += state.size;
		}
		else
			state.base = -2;			// We have no anchor
		int cur_rightmost = state.cur_rightmost;
		int cur_size = state.size;
		res = right.resolveOperandLeft(state);
		if (!res) return false;
		state.base = cur_base;			// Restore base and offset
		state.offset = cur_offset;
		if (state.cur_rightmost == -1) {
			if ((state.size != -1)&&(cur_rightmost != -1)&&(cur_size != -1)) {
				state.cur_rightmost = cur_rightmost;
				state.size += cur_size;
			}
		}
		return true;
	}
}
