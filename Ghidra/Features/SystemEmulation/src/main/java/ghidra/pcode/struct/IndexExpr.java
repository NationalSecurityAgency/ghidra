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
import ghidra.pcode.struct.StructuredSleigh.RVal;
import ghidra.program.model.data.DataType;

class IndexExpr extends Expr implements LValInternal {
	private final RValInternal base;
	private final RValInternal index;
	private final int elemLen;

	private IndexExpr(StructuredSleigh ctx, RVal base, RVal index, int elemLen, DataType type) {
		super(ctx, type);
		this.base = (RValInternal) base;
		this.index = (RValInternal) index;
		this.elemLen = elemLen;
	}

	protected IndexExpr(StructuredSleigh ctx, RVal base, RVal index) {
		this(ctx, base, index, ctx.computeElementLength(base), base.getType());
	}

	@Override
	public LVal cast(DataType type) {
		return new IndexExpr(ctx, base, index, elemLen, type);
	}

	@Override
	public String toString() {
		return "<Index " + base + " 0x" + Long.toString(elemLen, 16) + "*" + index + ">";
	}

	@Override
	public StringTree generate(RValInternal parent) {
		StringTree st = new StringTree();
		st.append("(");
		st.append(base.generate(this));
		st.append(" + (");
		st.append(index.generate(this));
		st.append("*");
		st.append(Integer.toString(elemLen));
		st.append("))");
		return st;
	}
}
