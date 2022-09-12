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

import ghidra.pcode.struct.StructuredSleigh.*;

class IfStmt extends ConditionalStmt {
	protected AbstractStmt elseStmt;

	protected IfStmt(StructuredSleigh ctx, RVal cond, Stmt stmt) {
		super(ctx, cond, stmt);
	}

	@Override
	protected StringTree generate(Label next, Label fall) {
		StringTree st = new StringTree();
		if (elseStmt == null) {
			if (stmt.isSingleGoto()) {
				return stmt.getNext().genGoto(cond, fall);
			}

			Label lTrue = ctx.new FreshLabel();
			Label lFalse = next.freshOrBorrow();

			StringTree condGen = lFalse.genGoto(cond.notb(), lTrue);
			StringTree stmtGen = stmt.generate(next, fall);

			st.append(condGen);
			st.append(lTrue.genAnchor());
			st.append(stmtGen);
			st.append(lFalse.genAnchor());
		}
		else {
			Label lFalse = ctx.new FreshLabel();
			Label lTrue = ctx.new FreshLabel();
			Label lExit = next.freshOrBorrow();

			StringTree condGen = lTrue.genGoto(cond, lFalse);
			StringTree elseGen = elseStmt.generate(lExit, lTrue);
			StringTree stmtGen = stmt.generate(next, fall);

			st.append(condGen);
			st.append(lFalse.genAnchor());
			st.append(elseGen);
			st.append(lTrue.genAnchor());
			st.append(stmtGen);
			st.append(lExit.genAnchor());
		}
		return st;
	}

	protected void addElse(Stmt elseStmt) {
		assert this.elseStmt == null;
		this.elseStmt = ((AbstractStmt) elseStmt).reparent(this);
	}
}
