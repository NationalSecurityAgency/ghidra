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
	protected String generate(Label next, Label fall) {
		if (elseStmt == null) {
			if (stmt.isSingleGoto()) {
				return stmt.getNext().genGoto(cond, fall);
			}

			Label lTrue = ctx.new FreshLabel();
			Label lFalse = next.freshOrBorrow();

			String condGen = lFalse.genGoto(cond.notb(), lTrue);
			String stmtGen = stmt.generate(next, fall);
			return condGen +
				lTrue.genAnchor() +
				stmtGen +
				lFalse.genAnchor();
		}

		Label lFalse = ctx.new FreshLabel();
		Label lTrue = ctx.new FreshLabel();
		Label lExit = next.freshOrBorrow();

		String condGen = lTrue.genGoto(cond, lFalse);
		String elseGen = elseStmt.generate(lExit, lTrue);
		String stmtGen = stmt.generate(next, fall);

		return condGen +
			lFalse.genAnchor() +
			elseGen +
			lTrue.genAnchor() +
			stmtGen +
			lExit.genAnchor();
	}

	protected void addElse(Stmt elseStmt) {
		assert this.elseStmt == null;
		this.elseStmt = ((AbstractStmt) elseStmt).reparent(this);
	}
}
