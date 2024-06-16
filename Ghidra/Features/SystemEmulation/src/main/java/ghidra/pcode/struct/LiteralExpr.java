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

class LiteralExpr extends Expr {
	private final long val;
	private final int size;

	protected LiteralExpr(StructuredSleigh ctx, long val, int size, DataType type) {
		super(ctx, type);
		this.val = val;
		this.size = size;
	}

	@Override
	public RVal cast(DataType type) {
		return new LiteralExpr(ctx, val, size, type);
	}

	@Override
	public String toString() {
		return "<Literal " + val + ":" + size + ">";
	}

	@Override
	public StringTree generate(RValInternal parent) {
		return StringTree.single(String.format("0x%x:%d", val, size));
	}
}
