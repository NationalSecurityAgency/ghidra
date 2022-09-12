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

import java.util.ArrayList;
import java.util.List;

import ghidra.pcode.struct.StructuredSleigh.Label;

/**
 * A block statement
 */
class BlockStmt extends AbstractStmt {
	List<AbstractStmt> children = new ArrayList<>();

	/**
	 * Build a block statement
	 * 
	 * @param ctx the context
	 * @param body the body, usually a lambda
	 */
	protected BlockStmt(StructuredSleigh ctx, Runnable body) {
		super(ctx);
		ctx.stack.push(this);
		body.run();
		ctx.stack.pop();
	}

	/**
	 * Add a child to this statement
	 * 
	 * @param child the child statement
	 */
	public void addChild(AbstractStmt child) {
		children.add(child);
	}

	@Override
	protected StringTree generate(Label next, Label fall) {
		if (children.isEmpty()) {
			return next.genGoto(fall);
		}
		StringTree st = new StringTree();
		for (AbstractStmt c : children.subList(0, children.size() - 1)) {
			st.append(c.generate(ctx.FALL, ctx.FALL));
		}
		st.append(children.get(children.size() - 1).generate(next, fall));
		return st;
	}

	@Override
	protected boolean isSingleGoto() {
		return children.size() == 1 && children.get(0).isSingleGoto();
	}

	@Override
	protected Label getNext() {
		return children.isEmpty() ? ctx.FALL : children.get(children.size() - 1).getNext();
	}
}
