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

class ForStmt extends LoopStmt {
	private final AbstractStmt init;
	private final AbstractStmt step;

	protected ForStmt(StructuredSleigh ctx, Stmt init, RVal cond, Stmt step,
			AbstractStmt stmt) {
		super(ctx, cond, stmt);
		this.init = ((AbstractStmt) init).reparent(this);
		this.step = ((AbstractStmt) step).reparent(this);
	}

	@Override
	protected String generate(Label next, Label fall) {
		Label lTest = ctx.new FreshLabel();
		Label lBegin = ctx.new FreshLabel();
		Label lExit = lBreak = next.freshOrBorrow();
		Label lStep = lContinue = ctx.new FreshLabel();

		String initGen = init.generate(lTest, lTest);
		String testGen = lExit.genGoto(cond.notb(), lBegin);
		String stmtGen = stmt.generate(lStep, lStep);
		String stepGen = step.generate(lTest, fall);
		return initGen +
			lTest.genAnchor() +
			testGen +
			lBegin.genAnchor() +
			stmtGen +
			lStep.genAnchor() +
			stepGen +
			lExit.genAnchor();
	}
}
