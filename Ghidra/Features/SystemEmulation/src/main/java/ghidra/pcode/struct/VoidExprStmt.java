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

class VoidExprStmt extends AbstractStmt implements RValInternal, StmtWithVal {
	private final RValInternal expr;
	private final DataType type;

	private VoidExprStmt(StructuredSleigh ctx, RVal expr, DataType type) {
		super(ctx);
		this.expr = (RValInternal) expr;
		this.type = type;
	}

	protected VoidExprStmt(StructuredSleigh ctx, RVal expr) {
		this(ctx, expr, expr.getType());
	}

	@Override
	public RVal cast(DataType type) {
		return new VoidExprStmt(ctx, expr, type);
	}

	@Override
	public String toString() {
		return "<VoidExpr " + expr + ">";
	}

	@Override
	protected StringTree generate(Label next, Label fall) {
		StringTree st = new StringTree();
		st.append(expr.generate(this));
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
		return ctx.nil.generate(this);
	}
}
