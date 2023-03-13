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
import ghidra.program.model.data.DataType;

/**
 * An assignment statement
 */
class AssignStmt extends AbstractStmt implements RValInternal, StmtWithVal {
	final LValInternal lhs;
	private final RValInternal rhs;
	private final DataType type;

	private AssignStmt(StructuredSleigh ctx, LVal lhs, RVal rhs, DataType type) {
		super(ctx);
		this.lhs = (LValInternal) lhs;
		this.rhs = (RValInternal) rhs;
		this.type = type;
	}

	public AssignStmt(StructuredSleigh ctx, LVal lhs, RVal rhs) {
		// NOTE: Takes the type of the left-hand side
		this(ctx, lhs, rhs, lhs.getType());
	}

	@Override
	public RVal cast(DataType type) {
		return new AssignStmt(ctx, lhs, rhs, type);
	}

	@Override
	public String toString() {
		return "<Assign " + lhs + " = " + rhs + ">";
	}

	@Override
	protected StringTree generate(Label next, Label fall) {
		StringTree st = new StringTree();
		st.append(lhs.generate(this));
		st.append(" = ");
		st.append(rhs.generate(this));
		st.append(";\n");
		st.append(next.genGoto(fall));
		return st;
	}

	@Override
	public DataType getType() {
		return type;
	}

	@Override
	public StringTree generate(RValInternal parent) {
		return lhs.generate(this);
	}
}
