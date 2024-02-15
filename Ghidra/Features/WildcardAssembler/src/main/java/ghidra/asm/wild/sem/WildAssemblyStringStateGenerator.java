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

import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol;
import ghidra.asm.wild.tree.WildAssemblyParseToken;

public class WildAssemblyStringStateGenerator
		extends AbstractAssemblyStateGenerator<WildAssemblyParseToken> {

	protected final OperandSymbol opSym;
	protected final String val;

	public WildAssemblyStringStateGenerator(AbstractAssemblyTreeResolver<?> resolver,
			WildAssemblyParseToken node, OperandSymbol opSym, String val,
			AssemblyResolvedPatterns fromLeft) {
		super(resolver, node, fromLeft);
		this.opSym = opSym;
		this.val = val;
	}

	@Override
	public Stream<AssemblyGeneratedPrototype> generate(GeneratorContext gc) {
		if (!node.wild.test(val)) {
			return Stream.of();
		}
		return Stream.of(new AssemblyGeneratedPrototype(new WildAssemblyOperandState(resolver,
			gc.path, gc.shift, node.getSym(), 0, opSym, node.wildcardName(), val), fromLeft));
	}
}
