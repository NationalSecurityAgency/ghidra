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

import java.util.stream.Stream;

import ghidra.app.plugin.assembler.sleigh.sem.AssemblyGeneratedPrototype;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns;
import ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol;
import ghidra.asm.wild.tree.WildAssemblyParseToken;
import ghidra.asm.wild.tree.WildAssemblyParseToken.*;

public class WildAssemblyNumericStateGenerator extends WildAssemblyNopStateGenerator {

	public WildAssemblyNumericStateGenerator(WildAssemblyTreeResolver resolver,
			WildAssemblyParseToken node, OperandSymbol opSym, String wildcard,
			AssemblyResolvedPatterns fromLeft) {
		super(resolver, node, opSym, wildcard, fromLeft);
	}

	@Override
	public Stream<AssemblyGeneratedPrototype> generate(GeneratorContext gc) {
		if (node.wild instanceof RegexWildcard) {
			return Stream.of();
		}
		if (node.wild instanceof FreeWildcard || node.wild instanceof NumericWildcard) {
			return super.generate(gc);
		}
		if (node.wild instanceof RangesWildcard wild) {
			return wild.stream()
					.mapToObj(v -> new AssemblyGeneratedPrototype(new WildAssemblyOperandState(
						resolver, gc.path, gc.shift, node.getSym(), v, opSym, node.wildcardName(),
						v), fromLeft));
		}
		throw new AssertionError();
	}
}
