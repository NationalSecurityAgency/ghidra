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

import ghidra.pcode.struct.StructuredSleigh.Label;

class RawStmt extends AbstractStmt {
	private final String stmt;

	protected RawStmt(StructuredSleigh ctx, String stmt) {
		super(ctx);
		this.stmt = stmt;
	}

	@Override
	protected StringTree generate(Label next, Label fall) {
		StringTree st = new StringTree();
		st.append(stmt);
		st.append(";\n");
		st.append(next.genGoto(fall));
		return st;
	}
}
