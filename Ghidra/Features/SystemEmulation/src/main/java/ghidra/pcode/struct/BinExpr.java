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

import ghidra.pcode.struct.StructuredSleigh.RVal;
import ghidra.program.model.data.DataType;

class BinExpr extends Expr {
	protected final RValInternal lhs;
	protected final String op;
	protected final RValInternal rhs;

	protected BinExpr(StructuredSleigh ctx, RVal lhs, String op, RVal rhs, DataType type) {
		super(ctx, type);
		this.lhs = (RValInternal) lhs;
		this.op = op;
		this.rhs = (RValInternal) rhs;
	}

	@Override
	public RVal cast(DataType type) {
		return new BinExpr(ctx, lhs, op, rhs, type);
	}

	@Override
	public String toString() {
		return "<" + getClass().getSimpleName() + " " + lhs + " " + op + " " + rhs + ">";
	}

	@Override
	public StringTree generate(RValInternal parent) {
		StringTree st = new StringTree();
		st.append("(");
		st.append(lhs.generate(this));
		st.append(" ");
		st.append(op);
		st.append(" ");
		st.append(rhs.generate(this));
		st.append(")");
		return st;
	}
}
