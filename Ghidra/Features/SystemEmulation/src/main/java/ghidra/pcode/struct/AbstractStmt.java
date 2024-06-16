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
package ghidra.pcode.struct;

import ghidra.lifecycle.Internal;
import ghidra.pcode.struct.StructuredSleigh.Label;
import ghidra.pcode.struct.StructuredSleigh.Stmt;

abstract class AbstractStmt implements Stmt {
	protected final StructuredSleigh ctx;
	protected AbstractStmt parent;

	protected AbstractStmt(StructuredSleigh ctx) {
		this.ctx = ctx;
		BlockStmt parent = ctx.stack.peek();
		this.parent = parent;
		if (parent != null) {
			parent.children.add(this);
		}
	}

	/**
	 * Internal: Provides the implementation of {@link RValInternal#getContext()} for
	 * {@link AssignStmt}
	 * 
	 * @return the context
	 */
	public StructuredSleigh getContext() {
		return ctx;
	}

	@Internal
	protected AbstractStmt reparent(AbstractStmt newParent) {
		assert parent instanceof BlockStmt;
		BlockStmt parent = (BlockStmt) this.parent;
		parent.children.remove(this);
		this.parent = newParent;
		return this;
	}

	/**
	 * Get the innermost statement of the given class containing this statement
	 * 
	 * <p>
	 * This is used to implement "truncation" statements like "break", "continue", and "result".
	 * 
	 * @param <T> the type of the statement sought
	 * @param cls the class of the statement sought
	 * @return the found statement or null
	 */
	@Internal
	protected <T extends Stmt> T nearest(Class<T> cls) {
		if (cls.isAssignableFrom(this.getClass())) {
			return cls.cast(this);
		}
		if (parent == null) {
			return null;
		}
		return parent.nearest(cls);
	}

	/**
	 * Generate the Sleigh code that implements this statement
	 * 
	 * @param next the label receiving control immediately after this statement is executed
	 * @param fall the label positioned immediately after this statement in the generated code
	 * @return the generated Sleigh code
	 */
	protected abstract StringTree generate(Label next, Label fall);

	/**
	 * Check if the statement is or contains a single branch statement
	 * 
	 * <p>
	 * This is to avoid the unnecessary generation of labels forming chains of unconditional gotos.
	 * 
	 * @return true if so, false otherwise.
	 */
	protected boolean isSingleGoto() {
		return false;
	}

	/**
	 * Get the label for the statement immediately following this statement
	 * 
	 * <p>
	 * For statements that always fall-through, this is just {#link {@link StructuredSleigh#FALL}.
	 * 
	 * @return the label
	 */
	protected Label getNext() {
		return ctx.FALL;
	}
}
