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

import ghidra.app.plugin.assembler.sleigh.util.DbgTimer;

/**
 * Base for a node in an assembly prototype
 */
public abstract class AbstractAssemblyState {
	protected static final DbgTimer DBG = AbstractAssemblyTreeResolver.DBG;

	protected final AbstractAssemblyTreeResolver<?> resolver;
	protected final AbstractAssemblyResolutionFactory<?, ?> factory;
	protected final List<AssemblyConstructorSemantic> path;
	protected final int shift;
	protected final int length;

	protected volatile boolean hasHash = false;
	protected volatile int hash;

	/**
	 * Construct a node
	 * 
	 * @param resolver the resolver
	 * @param path the path to this node for diagnostics
	 * @param shift the (right) shift in bytes for this operand
	 * @param length the length of this operand
	 */
	protected AbstractAssemblyState(AbstractAssemblyTreeResolver<?> resolver,
			List<AssemblyConstructorSemantic> path, int shift, int length) {
		this.resolver = resolver;
		this.factory = resolver.factory;
		this.path = path;
		this.shift = shift;
		this.length = length;
	}

	@Override
	public int hashCode() {
		if (!hasHash) {
			this.hash = computeHash();
			this.hasHash = true;
		}
		return hash;
	}

	/**
	 * Pre compute this nodes hash
	 * 
	 * @return the hash
	 */
	public abstract int computeHash();

	@Override
	public abstract boolean equals(Object obj);

	/**
	 * Generate machine (partial) code for this node
	 * 
	 * @param fromRight the accumulated patterns thus far, from the right sibling or left-most child
	 * @param errors a place to collect error reports
	 * @return the stream of generated patterns, as accumulated
	 */
	protected abstract Stream<AssemblyResolvedPatterns> resolve(AssemblyResolvedPatterns fromRight,
			Collection<AssemblyResolvedError> errors);

	public AbstractAssemblyTreeResolver<?> getResolver() {
		return resolver;
	}

	public List<AssemblyConstructorSemantic> getPath() {
		return path;
	}

	public int getShift() {
		return shift;
	}

	/**
	 * Get the length in bytes of the operand represented by this node
	 * 
	 * @return the length
	 */
	public int getLength() {
		return length;
	}
}
