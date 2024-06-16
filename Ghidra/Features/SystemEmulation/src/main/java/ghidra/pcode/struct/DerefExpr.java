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

import ghidra.pcode.struct.StructuredSleigh.LVal;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;

class DerefExpr extends Expr implements LValInternal {
	private final AddressSpace space;
	private final RValInternal addr;

	private DerefExpr(StructuredSleigh ctx, AddressSpace space, RValInternal addr,
			DataType type) {
		super(ctx, type);
		this.space = space;
		this.addr = addr;
	}

	protected DerefExpr(StructuredSleigh ctx, AddressSpace space, RValInternal addr) {
		this(ctx, space, addr, ctx.computeDerefType(addr));
	}

	@Override
	public LVal cast(DataType type) {
		return new DerefExpr(ctx, space, addr, type);
	}

	@Override
	public String toString() {
		return "<Deref *" + addr + ">";
	}

	@Override
	public StringTree generate(RValInternal parent) {
		StringTree st = new StringTree();
		boolean useParens = !(parent instanceof AssignStmt as && as.lhs == this);
		if (useParens) {
			st.append("(*");
		}
		else {
			st.append("*");
		}
		if (ctx.language.getDefaultSpace() != space) {
			st.append("[");
			st.append(space.getName());
			st.append("]");
		}
		if (type.getLength() != 0) {
			st.append(":");
			st.append(Integer.toString(type.getLength()));
		}
		st.append(" ");
		st.append(addr.generate(this));
		if (useParens) {
			st.append(")");
		}
		return st;
	}
}
