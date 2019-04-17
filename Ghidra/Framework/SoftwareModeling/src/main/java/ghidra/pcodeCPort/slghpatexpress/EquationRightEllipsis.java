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

public class EquationRightEllipsis extends PatternEquation {

	private PatternEquation eq;

	@Override
	public void dispose() {
		super.release(eq);
	}

	public EquationRightEllipsis(Location location, PatternEquation e) {
		super(location);
		(eq = e).layClaim();
	}

	@Override
	public void genPattern(VectorSTL<TokenPattern> ops) {
		eq.genPattern(ops);
		setTokenPattern(eq.getTokenPattern());
		getTokenPattern().setRightEllipsis(true);
	}

	@Override
	public void operandOrder(Constructor ct, VectorSTL<OperandSymbol> order) {
		eq.operandOrder(ct, order); // List operands
	}

	@Override
	public boolean resolveOperandLeft(OperandResolve state) {
		boolean res = eq.resolveOperandLeft(state);
		if (!res) return false;
		state.size = -1;		// Cannot predict size
		return true;
	}
}
