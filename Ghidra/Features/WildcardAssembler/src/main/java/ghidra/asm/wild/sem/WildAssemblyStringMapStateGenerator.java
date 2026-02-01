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

import org.apache.commons.collections4.MultiValuedMap;

import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol;
import ghidra.asm.wild.tree.WildAssemblyParseToken;
import ghidra.asm.wild.tree.WildAssemblyParseToken.NumericWildcard;
import ghidra.asm.wild.tree.WildAssemblyParseToken.RangesWildcard;

public class WildAssemblyStringMapStateGenerator
		extends AbstractAssemblyStateGenerator<WildAssemblyParseToken> {

	protected final OperandSymbol opSym;
	protected final MultiValuedMap<String, Integer> map;

	public WildAssemblyStringMapStateGenerator(WildAssemblyTreeResolver resolver,
			WildAssemblyParseToken node, OperandSymbol opSym, MultiValuedMap<String, Integer> map,
			AssemblyResolvedPatterns fromLeft) {
		super(resolver, node, fromLeft);
		this.opSym = opSym;
		this.map = map;
	}

	@Override
	public Stream<AssemblyGeneratedPrototype> generate(GeneratorContext gc) {
		// TODO: If all values are represented, perhaps just leave the bits unspecified.
		// I'll lose the choice information, though....
		if (node.wild instanceof RangesWildcard || node.wild instanceof NumericWildcard) {
			return Stream.of();
		}
		return map.entries()
				.stream()
				.filter(e -> node.wild.test(e.getKey()))
				.map(e -> new AssemblyGeneratedPrototype(
					new WildAssemblyOperandState(resolver, gc.path, gc.shift, node.getSym(),
						e.getValue(), opSym, node.wildcardName(), e.getKey()),
					fromLeft));
	}
}
