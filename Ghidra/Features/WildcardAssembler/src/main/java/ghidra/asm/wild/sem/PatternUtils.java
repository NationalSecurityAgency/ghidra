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
package ghidra.asm.wild.sem;

import ghidra.app.plugin.assembler.sleigh.expr.MaskedLong;
import ghidra.app.plugin.assembler.sleigh.expr.OperandValueSolver;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.expression.*;
import ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol;

public class PatternUtils {
	private PatternUtils() {
	}

	public static WildAssemblyResolvedPatterns castWild(AssemblyResolvedPatterns rp) {
		return (WildAssemblyResolvedPatterns) rp;
	}

	public static AssemblyPatternBlock collectLocation(PatternExpression exp) {
		if (exp instanceof BinaryExpression bin) {
			return collectLocation(bin.getLeft()).combine(collectLocation(bin.getRight()));
		}
		if (exp instanceof UnaryExpression un) {
			return collectLocation(un.getUnary());
		}
		if (exp instanceof ContextField cf) {
			// TODO: I'm not sure how to capture info for operands that go temporarily into context
			return AssemblyPatternBlock.nop();
		}
		if (exp instanceof TokenField tf) {
			return AssemblyPatternBlock.fromTokenField(tf, MaskedLong.ONES);
		}
		if (exp instanceof OperandValue ov) {
			// I still have a lot of uncertainty as to what an OperandValue is
			Constructor cons = ov.getConstructor();
			OperandSymbol sym = cons.getOperand(ov.getIndex());
			PatternExpression patexp = OperandValueSolver.getDefiningExpression(sym);
			return collectLocation(patexp).shift(AssemblyTreeResolver.computeOffset(sym, cons));
		}
		// constant, start, end, next2
		return AssemblyPatternBlock.nop();
	}
}
