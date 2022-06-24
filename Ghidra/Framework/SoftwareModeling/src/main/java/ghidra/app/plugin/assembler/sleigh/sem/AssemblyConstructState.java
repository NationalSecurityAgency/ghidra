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

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.app.plugin.processors.sleigh.ConstructState;

/**
 * The state corresponding to a sub-table operand
 * 
 * <p>
 * This is roughly analogous to {@link ConstructState}, but for assembly. It records the assembly
 * semantic, i.e., SLEIGH constructor, and the child states, one for each operand in the
 * constructor. It's implementation of {@link #resolve(AssemblyResolvedPatterns, Collection)}
 * encapsulates, perhaps the very kernel of, machine-code generation. Operands can have there own
 * complexity, but most of the core machine-code concepts of SLEIGH are handled by constructors.
 */
public class AssemblyConstructState extends AbstractAssemblyState {

	/**
	 * Compute the farthest end byte (exclusive) among the given operands
	 * 
	 * @param operands the operands
	 * @return the farthest end byte
	 */
	protected static int computeEnd(List<AbstractAssemblyState> operands) {
		return operands.stream()
				.map(s -> s.shift + s.length)
				.reduce(0, Integer::max);
	}

	protected final AssemblyConstructorSemantic sem;
	protected final List<AbstractAssemblyState> children;

	/**
	 * Construct the state for a selected SLEIGH constructor of a sub-table operand
	 * 
	 * <p>
	 * The operand's length is computed from the constructors length and the shifts and lengths of
	 * its generated operands.
	 * 
	 * @param resolver the resolver
	 * @param path the path for diagnostics
	 * @param shift the (right) shift of this operand
	 * @param sem the selected SLEIGH constructor
	 * @param children the child state for each operand in the constructor
	 */
	public AssemblyConstructState(AssemblyTreeResolver resolver,
			List<AssemblyConstructorSemantic> path, int shift,
			AssemblyConstructorSemantic sem, List<AbstractAssemblyState> children) {
		super(resolver, path, shift,
			Integer.max(computeEnd(children) - shift, sem.cons.getMinimumLength()));
		this.sem = sem;
		this.children = children;
	}

	@Override
	public int computeHash() {
		return Objects.hash(getClass(), shift, sem, children);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof AssemblyConstructState)) {
			return false;
		}
		AssemblyConstructState that = (AssemblyConstructState) obj;
		if (this.resolver != that.resolver) {
			return false;
		}
		if (this.shift != that.shift) {
			return false;
		}
		if (!Objects.equals(this.sem, that.sem)) {
			return false;
		}
		if (!Objects.equals(this.children, that.children)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return sem.getLocation() + "[" +
			children.stream().map(s -> s.toString()).collect(Collectors.joining(",")) + "]";
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Currently, this is used to generate machine-code from a generated assembly instruction
	 * prototype, but it is not used to apply recursive constructors, i.e., for prefix generation.
	 * TODO: That should change. This performs the reverse of the machine-code parsing process, both
	 * in concept and in implementation. First, it descends to the children. Each child is a
	 * {@link AbstractAssemblyState}, i.e., either another constructor, or a value operand. (There
	 * are also specializations for dealing with hidden constructor and value operands.) Then it
	 * solves context changes, in the reverse order of the specification. Finally, it applies the
	 * patterns, in order to satisfy the constraints specified by the constructor. As a final
	 * detail, it records, for diagnostic purposes, the intermediate child patterns into the parent
	 * pattern.
	 */
	@Override
	protected Stream<AssemblyResolvedPatterns> resolve(AssemblyResolvedPatterns fromRight,
			Collection<AssemblyResolvedError> errors) {
		String desc = "Resolving constructor: " + sem.getLocation();
		return resolveRemainingChildren(fromRight, errors, children)
				.flatMap(fromChildren -> resolveMutations(fromChildren, errors))
				.flatMap(fromMutations -> resolvePatterns(fromMutations, errors))
				.map(pat -> pat.parent(desc, children.size()).withConstructor(sem.cons));
	}

	/**
	 * Apply each possible pattern for the selected constructor
	 * 
	 * @param fromMutations the assembly pattern after mutations were solved
	 * @param errors a place to collect errors
	 * @return the stream of patterns, as accumulated with {@code fromMutations}
	 */
	protected Stream<AssemblyResolvedPatterns> resolvePatterns(
			AssemblyResolvedPatterns fromMutations, Collection<AssemblyResolvedError> errors) {
		return sem.getPatterns()
				.stream()
				.map(pat -> {
					DBG.println(path + ": Constructor pattern: " + pat.lineToString());
					DBG.println(path + ": Current     pattern: " + fromMutations.lineToString());
					AssemblyResolvedPatterns combined = fromMutations.combine(pat.shift(shift));
					//DBG.println("Combined    pattern: " + combined);
					return combined;
				})
				.filter(ar -> {
					if (ar == null) {
						errors.add(AssemblyResolution.error("Pattern conflict",
							"Resolving " + sem.getLocation() + " in " + path));
						return false;
					}
					return true;
				});
	}

	/**
	 * Solve the mutations for the selected constructor
	 * 
	 * @param fromChildren the assembly pattern as accumulated from the left-most child
	 * @param errors a place to collect errors
	 * @return the stream of patterns, as accumulated with {@code fromChildren}
	 */
	protected Stream<AssemblyResolvedPatterns> resolveMutations(
			AssemblyResolvedPatterns fromChildren, Collection<AssemblyResolvedError> errors) {
		AssemblyResolution ar = sem.solveContextChanges(fromChildren, resolver.vals);
		if (ar.isError()) {
			errors.add((AssemblyResolvedError) ar);
			return Stream.of();
		}
		if (ar.isBackfill()) {
			throw new AssertionError();
		}
		AssemblyResolvedPatterns pat = (AssemblyResolvedPatterns) ar;
		return Stream.of(pat.solveContextChangesForForbids(sem, resolver.vals));
	}

	/**
	 * A recursive function from resolving all children right-to-left and accumulating the patterns
	 * 
	 * <p>
	 * This pops the right-most child in {@code children}, resolves it, and then recurses, passing
	 * the accumulated patterns in as {@code fromRight} with the remaining children.
	 * {@link Stream#flatMap(java.util.function.Function)} makes this somewhat fluent, given the
	 * possibility of multiple resolutions.
	 * 
	 * @param fromRight the assembly pattern as accumulated from the right sibling. If this is the
	 *            right-most sibling, then this is the pattern accumulated from the parent's right
	 *            sibling, as so on. If no such sibling exists, it is the unrestricted (empty)
	 *            pattern.
	 * @param errors a place to collect errors
	 * @param children the remaining children to resolve
	 * @return the stream of accumulated patterns
	 */
	protected Stream<AssemblyResolvedPatterns> resolveRemainingChildren(
			AssemblyResolvedPatterns fromRight, Collection<AssemblyResolvedError> errors,
			List<AbstractAssemblyState> children) {

		// Need to resolve children (as they apply context changes) from right to left
		if (children.isEmpty()) {
			return Stream.of(fromRight);
		}

		AbstractAssemblyState rightMost = children.get(children.size() - 1);
		return rightMost.resolve(fromRight, errors).flatMap(fromChild -> {
			return resolveRemainingChildren(fromChild, errors,
				children.subList(0, children.size() - 1));
		});
	}
}
