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

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseTreeNode;
import ghidra.app.plugin.assembler.sleigh.util.DbgTimer;

/**
 * Base class for generating prototype nodes ("states") from a parse tree node
 *
 * @param <N> the type of parse tree node to process
 */
public abstract class AbstractAssemblyStateGenerator<N extends AssemblyParseTreeNode> {
	protected static final DbgTimer DBG = AssemblyTreeResolver.DBG;

	/**
	 * Context to pass along as states are generated
	 */
	protected static class GeneratorContext {

		/**
		 * Render the path as a printable string
		 * 
		 * @param path the path
		 * @return the string
		 */
		public static String pathToString(List<AssemblyConstructorSemantic> path) {
			return "[" +
				path.stream().map(sem -> sem.getLocation()).collect(Collectors.joining(",")) + "]";
		}

		final List<AssemblyConstructorSemantic> path;
		final int shift;

		/**
		 * Construct a context
		 * 
		 * @param path the path of constructors, for diagnostics
		 * @param shift the (right) shift in bytes of the operand whose state is being generated
		 */
		public GeneratorContext(List<AssemblyConstructorSemantic> path, int shift) {
			this.path = List.copyOf(path);
			this.shift = shift;
		}

		/**
		 * Construct a context suitable for descent into an operand
		 * 
		 * @param cons the parent constructor
		 * @param shift the shift offset of the operand
		 * @return the context
		 */
		public GeneratorContext push(AssemblyConstructorSemantic cons, int shift) {
			List<AssemblyConstructorSemantic> path = new ArrayList<>(this.path);
			path.add(cons);
			return new GeneratorContext(path, this.shift + shift);
		}

		/**
		 * Print a debug line
		 * 
		 * @param string the message
		 */
		public void dbg(String string) {
			DBG.println(pathToString(path) + ":" + string);
		}
	}

	protected final AssemblyTreeResolver resolver;
	protected final N node;
	protected final AssemblyResolvedPatterns fromLeft;

	/**
	 * Construct a generator
	 * 
	 * @param resolver the resolver
	 * @param node the node from which to generate states
	 * @param fromLeft the accumulated patterns from the left sibling or the parent
	 */
	public AbstractAssemblyStateGenerator(AssemblyTreeResolver resolver, N node,
			AssemblyResolvedPatterns fromLeft) {
		this.resolver = resolver;
		this.node = node;
		this.fromLeft = fromLeft;
	}

	/**
	 * Generate states
	 * 
	 * @param gc the generator context for this node
	 * @return the stream of prototypes, each including accumulated patterns
	 */
	public abstract Stream<AssemblyGeneratedPrototype> generate(GeneratorContext gc);
}
