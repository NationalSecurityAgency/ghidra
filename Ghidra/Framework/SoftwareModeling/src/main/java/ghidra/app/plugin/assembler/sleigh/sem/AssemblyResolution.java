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

import java.util.List;
import java.util.Map;

import ghidra.app.plugin.assembler.sleigh.expr.MaskedLong;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern;

/**
 * The (often intermediate) result of assembly
 * 
 * These may represent a successful construction ({@link AssemblyResolvedConstructor}, a future
 * field ({@link AssemblyResolvedBackfill}), or an error ({@link AssemblyResolvedError}).
 * 
 * This class also provides the static factory methods for constructing any of its subclasses.
 */
public abstract class AssemblyResolution implements Comparable<AssemblyResolution> {
	protected final String description;
	protected final List<? extends AssemblyResolution> children;

	private boolean hashed = false;
	private int hash;

	@Override
	public int hashCode() {
		if (!hashed) {
			hash = computeHash();
			hashed = true;
		}
		return hash;
	}

	protected abstract int computeHash();

	/**
	 * Construct a resolution
	 * @param description a textual description used as part of {@link #toString()}
	 * @param children for record keeping, any children used in constructing this resolution
	 */
	AssemblyResolution(String description, List<? extends AssemblyResolution> children) {
		this.description = description;
		this.children = children == null ? List.of() : children;
	}

	/* ********************************************************************************************
	 * Static factory methods
	 */

	/**
	 * Build the result of successfully resolving a SLEIGH constructor
	 * 
	 * NOTE: This is not used strictly for resolved SLEIGH constructors. It may also be used to
	 * store intermediates, e.g., encoded operands, during constructor resolution.
	 * @param ins the instruction pattern block
	 * @param ctx the context pattern block
	 * @param description a description of the resolution
	 * @param sel the children selected to resolve this constructor, or null
	 * @return the new resolution
	 */
	public static AssemblyResolvedConstructor resolved(AssemblyPatternBlock ins,
			AssemblyPatternBlock ctx, String description,
			List<? extends AssemblyResolution> sel) {
		return new AssemblyResolvedConstructor(description, sel, ins, ctx, null, null);
	}

	/**
	 * Build an instruction-only successful resolution result
	 * @see #resolved(AssemblyPatternBlock, AssemblyPatternBlock, String, List)
	 * @param ins the instruction pattern block
	 * @param description a description of the resolution
	 * @param children the children selected to resolve this constructor, or null
	 * @return the new resolution
	 */
	public static AssemblyResolvedConstructor instrOnly(AssemblyPatternBlock ins,
			String description, List<AssemblyResolution> children) {
		return resolved(ins, AssemblyPatternBlock.nop(), description, children);
	}

	/**
	 * Build a context-only successful resolution result
	 * @see #resolved(AssemblyPatternBlock, AssemblyPatternBlock, String, List)
	 * @param ctx the context pattern block
	 * @param description a description of the resolution
	 * @param children the children selected to resolve this constructor, or null
	 * @return the new resolution
	 */
	public static AssemblyResolvedConstructor contextOnly(AssemblyPatternBlock ctx,
			String description, List<AssemblyResolution> children) {
		return resolved(AssemblyPatternBlock.nop(), ctx, description, children);
	}

	/**
	 * Build a successful resolution result from a SLEIGH constructor's patterns
	 * @param pat the constructor's pattern
	 * @param description a description of the resolution
	 * @return the new resolution
	 */
	public static AssemblyResolvedConstructor fromPattern(DisjointPattern pat, int minLen,
			String description) {
		AssemblyPatternBlock ins = AssemblyPatternBlock.fromPattern(pat, minLen, false);
		AssemblyPatternBlock ctx = AssemblyPatternBlock.fromPattern(pat, 0, true);
		return resolved(ins, ctx, description, null);
	}

	/**
	 * Build a backfill record to attach to a successful resolution result
	 * @param exp the expression depending on a missing symbol
	 * @param goal the desired value of the expression
	 * @param res the resolution result for child constructors
	 * @param inslen the length of instruction portion expected in the future solution
	 * @param description a description of the backfill record
	 * @return the new record
	 */
	public static AssemblyResolvedBackfill backfill(PatternExpression exp, MaskedLong goal,
			Map<Integer, Object> res, int inslen, String description) {
		return new AssemblyResolvedBackfill(description, exp, goal, res, inslen, 0);
	}

	/**
	 * Obtain a new "blank" resolved SLEIGH constructor record
	 * @param description a description of the resolution
	 * @param sel any children that will be involved in populating this record
	 * @return the new resolution
	 */
	public static AssemblyResolvedConstructor nop(String description,
			List<? extends AssemblyResolution> sel) {
		return resolved(AssemblyPatternBlock.nop(), AssemblyPatternBlock.nop(), description, sel);
	}

	/**
	 * Build an error resolution record
	 * @param error a description of the error
	 * @param description a description of what the resolver was doing when the error ocurred
	 * @param children any children involved in generating the error
	 * @return the new resolution
	 */
	public static AssemblyResolvedError error(String error, String description,
			List<? extends AssemblyResolution> children) {
		return new AssemblyResolvedError(description, children, error);
	}

	/**
	 * Build an error resolution record, based on an intermediate SLEIGH constructor record
	 * @param error a description of the error
	 * @param res the constructor record that was being populated when the error ocurred
	 * @return the new error resolution
	 */
	public static AssemblyResolution error(String error, AssemblyResolvedConstructor res) {
		return error(error, res.description, res.children);
	}

	/* ********************************************************************************************
	 * Abstract methods
	 */

	/**
	 * Check if this record describes an error
	 * @return true if the record is an error
	 */
	public abstract boolean isError();

	/**
	 * Check if this record describes a backfill
	 * @return true if the record is a backfill
	 */
	public abstract boolean isBackfill();

	/**
	 * Display the resolution result in one line (omitting child details)
	 * @return the display description
	 */
	protected abstract String lineToString();

	/* ********************************************************************************************
	 * Misc
	 */

	/**
	 * Get the child portion of {@link #toString()}
	 * 
	 * If a subclass has another, possible additional, notion of children that it would like to
	 * include in {@link #toString()}, it must override this method.
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

	/**
	 * Used only by parents: get a multi-line description of this record, indented
	 * @param indent the current indentation
	 * @return the indented description
	 */
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

	/**
	 * Describe this record including indented children, grandchildren, etc., each on its own line
	 */
	@Override
	public String toString() {
		return toString("");
	}

	@Override
	public int compareTo(AssemblyResolution that) {
		return this.toString().compareTo(that.toString()); // LAZY
	}

	/**
	 * Check if this record has children
	 * 
	 * If a subclass has another, possibly additional, notion of children that it would like to
	 * include in {@link #toString()}, it must override this method to return true when such
	 * children are present.
	 * @see #childrenToString(String)
	 * @return true if this record has children
	 */
	public boolean hasChildren() {
		if (children == null) {
			return false;
		}
		if (children.size() == 0) {
			return false;
		}
		return true;
	}
}
