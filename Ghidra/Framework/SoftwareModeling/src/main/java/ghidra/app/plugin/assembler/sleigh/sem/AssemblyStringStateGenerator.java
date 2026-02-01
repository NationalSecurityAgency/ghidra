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

import java.util.stream.Stream;

import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseToken;
import ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol;

public class AssemblyStringStateGenerator
		extends AbstractAssemblyStateGenerator<AssemblyParseToken> {
	protected final OperandSymbol opSym;

	public AssemblyStringStateGenerator(AbstractAssemblyTreeResolver<?> resolver,
			AssemblyParseToken node, OperandSymbol opSym, AssemblyResolvedPatterns fromLeft) {
		super(resolver, node, fromLeft);
		this.opSym = opSym;
	}

	@Override
	public Stream<AssemblyGeneratedPrototype> generate(GeneratorContext gc) {
		return Stream.of(new AssemblyGeneratedPrototype(
			new AssemblyOperandState(resolver, gc.path, gc.shift, node.getSym(), 0, opSym),
			fromLeft));
	}
}
