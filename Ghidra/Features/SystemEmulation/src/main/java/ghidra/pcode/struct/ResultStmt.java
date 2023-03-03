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

import java.util.Objects;

import ghidra.pcode.exec.SleighPcodeUseropDefinition;
import ghidra.pcode.struct.StructuredSleigh.Label;
import ghidra.pcode.struct.StructuredSleigh.RVal;

class ResultStmt extends AbstractStmt {
	private final RValInternal result;

	protected ResultStmt(StructuredSleigh ctx, RVal result) {
		super(ctx);
		this.result = (RValInternal) result;
	}

	@Override
	protected StringTree generate(Label next, Label fall) {
		RoutineStmt routine = Objects.requireNonNull(nearest(RoutineStmt.class));

		if (!ctx.isAssignable(routine.retType, result.getType())) {
			ctx.emitResultTypeMismatch(routine, result);
		}

		StringTree st = new StringTree();
		st.append(SleighPcodeUseropDefinition.OUT_SYMBOL_NAME);
		st.append(" = ");
		st.append(result.generate(null));
		st.append(";\n");
		st.append(routine.lReturn.genGoto(fall));
		return st;
	}
}
