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

import java.util.*;
import java.util.stream.Stream;

import ghidra.app.plugin.assembler.sleigh.expr.OperandValueSolver;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol;

public class WildAssemblyNopState extends AssemblyNopState {
	protected final OperandSymbol opSym; // super just uses it for length
	protected final String wildcard;

	public WildAssemblyNopState(AbstractAssemblyTreeResolver<?> resolver,
			List<AssemblyConstructorSemantic> path, int shift, OperandSymbol opSym,
			String wildcard) {
		super(resolver, path, shift, opSym);
		this.opSym = opSym;
		this.wildcard = Objects.requireNonNull(wildcard);
	}

	@Override
	public int computeHash() {
		int result = super.computeHash();
		result *= 31;
		result += wildcard.hashCode();
		return result;
	}

	protected boolean wildPartsEqual(WildAssemblyNopState that) {
		if (!partsEqual(that)) {
			return false;
		}
		if (!this.wildcard.equals(that.wildcard)) {
			return false;
		}
		return true;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (this.getClass() != obj.getClass()) {
			return false;
		}
		WildAssemblyNopState that = (WildAssemblyNopState) obj;
		return wildPartsEqual(that);
	}

	@Override
	public String toString() {
		return "WILD:" + super.toString();
	}

	protected WildAssemblyResolvedPatterns castWildPatterns(AssemblyResolvedPatterns rp) {
		return (WildAssemblyResolvedPatterns) rp;
	}

	@Override
	protected Stream<AssemblyResolvedPatterns> resolve(AssemblyResolvedPatterns fromRight,
			Collection<AssemblyResolvedError> errors) {
		PatternExpression symExp = OperandValueSolver.getDefiningExpression(opSym);
		AssemblyPatternBlock location = PatternUtils.collectLocation(symExp).shift(shift);
		return super.resolve(fromRight, errors)
				.map(PatternUtils::castWild)
				.map(r -> r.withWildInfo(wildcard, path, location, symExp, null));
	}
}
