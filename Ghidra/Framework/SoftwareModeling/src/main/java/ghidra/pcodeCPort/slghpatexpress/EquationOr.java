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

// Pattern Equations ORed together
public class EquationOr extends PatternEquation {

	private PatternEquation left;
	private PatternEquation right;

	public EquationOr(Location location, PatternEquation l, PatternEquation r) {
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
		setTokenPattern(left.getTokenPattern().doOr(right.getTokenPattern()));
	}

	@Override
	public void operandOrder(Constructor ct, VectorSTL<OperandSymbol> order) {
		left.operandOrder(ct, order); // List operands left
		right.operandOrder(ct, order); //  to right
	}

	@Override
	public boolean resolveOperandLeft(OperandResolve state) {
		int cur_rightmost = -1;		// Initially we don't know our rightmost
		int cur_size = -1;			//   or size traversed since rightmost
		boolean res = right.resolveOperandLeft(state);
		if (!res) return false;
		if ((state.cur_rightmost != -1)&&(state.size != -1)) {
			cur_rightmost = state.cur_rightmost;
			cur_size = state.size;
		}
		res = left.resolveOperandLeft(state);
		if (!res) return false;
		if ((state.cur_rightmost == -1)||(state.size == -1)) {
			state.cur_rightmost = cur_rightmost;
			state.size = cur_size;
		}
		return true;
	}

}
