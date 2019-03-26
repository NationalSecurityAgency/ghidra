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

// Equation that defines operand
public class OperandEquation extends PatternEquation {

	private int index;

	public OperandEquation(Location location, int ind) {
		super(location);
		index = ind;
	}

	@Override
	public void genPattern(VectorSTL<TokenPattern> ops) {
		setTokenPattern(ops.get(index));
	}

	@Override
	public void operandOrder(Constructor ct, VectorSTL<OperandSymbol> order) {
		OperandSymbol sym = ct.getOperand(index);
		if (!sym.isMarked()) {
			order.push_back(sym);
			sym.setMark();
		}
	}

	@Override
	public boolean resolveOperandLeft(OperandResolve state) {
		OperandSymbol sym = state.operands.get( index );
		if (sym.isOffsetIrrelevant()) {
			sym.offsetbase = -1;
			sym.reloffset = 0;
			return true;
		}
		if (state.base==-2)		// We have no base
			return false;
		sym.offsetbase = state.base;
		sym.reloffset = state.offset;
		state.cur_rightmost = index;
		state.size = 0;		// Distance from right edge
		return true;
	}
}
