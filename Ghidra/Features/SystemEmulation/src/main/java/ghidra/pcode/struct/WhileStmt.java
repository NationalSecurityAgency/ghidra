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

class WhileStmt extends LoopStmt {
	protected WhileStmt(StructuredSleigh ctx, RVal cond, Stmt stmt) {
		super(ctx, cond, stmt);
	}

	@Override
	protected StringTree generate(Label next, Label fall) {
		Label lTest = lContinue = ctx.new FreshLabel();
		Label lBegin = ctx.new FreshLabel();
		Label lExit = lBreak = next.freshOrBorrow();

		StringTree testGen = lExit.genGoto(cond.notb(), lBegin);
		StringTree stmtGen = stmt.generate(lTest, fall);

		StringTree st = new StringTree();

		st.append(lTest.genAnchor());
		st.append(testGen);
		st.append(lBegin.genAnchor());
		st.append(stmtGen);
		st.append(lExit.genAnchor());
		return st;
	}
}
