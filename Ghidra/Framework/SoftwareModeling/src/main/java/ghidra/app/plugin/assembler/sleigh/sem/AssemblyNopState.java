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
package ghidra.app.plugin.assembler.sleigh.sem;

import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol;

public class AssemblyNopState extends AbstractAssemblyState {
	public AssemblyNopState(AssemblyTreeResolver resolver, List<AssemblyConstructorSemantic> path,
			int shift, OperandSymbol opSym) {
		super(resolver, path, shift, opSym.getMinimumLength());
	}

	@Override
	public int computeHash() {
		return "NOP".hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof AssemblyNopState)) {
			return false;
		}
		AssemblyNopState that = (AssemblyNopState) obj;
		if (this.resolver != that.resolver) {
			return false;
		}
		if (this.shift != that.shift) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "NOP";
	}

	@Override
	protected Stream<AssemblyResolvedPatterns> resolve(AssemblyResolvedPatterns fromRight,
			Collection<AssemblyResolvedError> errors) {
		return Stream.of(fromRight.nopLeftSibling());
	}
}
