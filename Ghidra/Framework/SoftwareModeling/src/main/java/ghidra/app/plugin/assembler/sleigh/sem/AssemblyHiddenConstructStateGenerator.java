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

import java.util.Arrays;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseTreeNode;
import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol;

/**
 * The generator of {@link AssemblyConstructState} for a hidden sub-table operand
 * 
 * <p>
 * In short, this exhausts all possible constructors in the given sub-table. For well-designed
 * languages, such exhaustion produces a very small set of possibilities. In general, hidden
 * sub-table operands are a bad idea.
 */
public class AssemblyHiddenConstructStateGenerator extends AssemblyConstructStateGenerator {
	protected final SubtableSymbol subtableSym;

	/**
	 * Construct the hidden sub-table operand state generator
	 * 
	 * @param resolver the resolver
	 * @param node the node from which to generate states
	 * @param fromLeft the accumulated patterns from the left sibling or the parent
	 */
	public AssemblyHiddenConstructStateGenerator(AssemblyTreeResolver resolver,
			SubtableSymbol subtableSym, AssemblyResolvedPatterns fromLeft) {
		super(resolver, null, fromLeft);
		this.subtableSym = subtableSym;
	}

	@Override
	public Stream<AssemblyGeneratedPrototype> generate(GeneratorContext gc) {
		return IntStream.range(0, subtableSym.getNumConstructors())
				.mapToObj(subtableSym::getConstructor)
				.map(resolver.grammar::getSemantic)
				.flatMap(sem -> applyConstructor(gc, sem));
	}

	@Override
	protected List<AssemblyParseTreeNode> orderOpNodes(AssemblyConstructorSemantic sem) {
		// Just provide null operands, since they're hidden, too.
		Constructor cons = sem.getConstructor();
		return Arrays.asList(new AssemblyParseTreeNode[cons.getNumOperands()]);
	}
}
