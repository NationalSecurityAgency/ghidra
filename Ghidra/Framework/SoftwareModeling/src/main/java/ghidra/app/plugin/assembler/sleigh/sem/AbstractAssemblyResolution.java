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

/**
 * The (often intermediate) result of assembly
 * 
 * <p>
 * These may represent a successful construction ({@link AssemblyResolvedPatterns}, a future field
 * ({@link AssemblyResolvedBackfill}), or an error ({@link AssemblyResolvedError}).
 * 
 * <p>
 * This class also provides the static factory methods for constructing any of its subclasses.
 */
public abstract class AbstractAssemblyResolution implements AssemblyResolution {
	protected final AbstractAssemblyResolutionFactory<?, ?> factory;
	protected final String description;
	protected final List<AssemblyResolution> children;
	protected final AssemblyResolution right;

	private boolean hashed = false;
	private int hash;

	/**
	 * Construct a resolution
	 * 
	 * @param description a textual description used as part of {@link #toString()}
	 * @param children for record keeping, any children used in constructing this resolution
	 */
	protected AbstractAssemblyResolution(AbstractAssemblyResolutionFactory<?, ?> factory,
			String description, List<? extends AssemblyResolution> children,
			AssemblyResolution right) {
		this.factory = factory;
		this.description = description;
		this.children = children == null ? List.of() : Collections.unmodifiableList(children);
		this.right = right;
	}

	@Override
	public int hashCode() {
		if (!hashed) {
			hash = computeHash();
			hashed = true;
		}
		return hash;
	}

	protected abstract int computeHash();

	/* ********************************************************************************************
	 * Misc
	 */

	protected List<AssemblyResolution> getAllRight() {
		List<AssemblyResolution> result = new ArrayList<>();
		collectAllRight(result);
		return result;
	}

	@Override
	public void collectAllRight(Collection<AssemblyResolution> into) {
		into.add(this);
		if (right == null) {
			return;
		}
		right.collectAllRight(into);
	}

	/**
	 * Get the child portion of {@link #toString()}
	 * 
	 * <p>
	 * If a subclass has another, possible additional, notion of children that it would like to
	 * include in {@link #toString()}, it must override this method.
	 * 
	 * @see #hasChildren()
	 * @param indent the current indentation
	 * @return the indented description for each child on its own line
	 */
	protected String childrenToString(String indent) {
		StringBuilder sb = new StringBuilder();
		for (AssemblyResolution child : children) {
			sb.append(child.toString(indent) + "\n");
		}
		return sb.substring(0, sb.length() - 1);
	}

	@Override
	public String toString(String indent) {
		StringBuilder sb = new StringBuilder();
		sb.append(indent);
		sb.append(lineToString());
		if (hasChildren()) {
			sb.append(":\n");
			String newIndent = indent + "  ";
			sb.append(childrenToString(newIndent));
		}
		return sb.toString();
	}

	@Override
	public String toString() {
		return toString("");
	}

	@Override
	public int compareTo(AssemblyResolution that) {
		return this.toString().compareTo(that.toString()); // LAZY
	}

	@Override
	public boolean hasChildren() {
		if (children == null) {
			return false;
		}
		if (children.size() == 0) {
			return false;
		}
		return true;
	}

	@Override
	public abstract AssemblyResolution shift(int amt);

	/**
	 * Get this same resolution, but without any right siblings
	 * 
	 * @return the resolution
	 */
	public AssemblyResolution withoutRight() {
		return withRight(null);
	}

	/**
	 * Get this same resolution, but with the given right sibling
	 * 
	 * @return the resolution
	 */
	public abstract AssemblyResolution withRight(AssemblyResolution right);

	@Override
	public String getDescription() {
		return description;
	}

	@Override
	public List<AssemblyResolution> getChildren() {
		return children;
	}

	@Override
	public AssemblyResolution getRight() {
		return right;
	}
}
