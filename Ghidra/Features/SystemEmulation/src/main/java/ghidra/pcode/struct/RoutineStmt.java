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
import ghidra.program.model.data.DataType;

class RoutineStmt extends BlockStmt {
	protected final String name;
	protected final DataType retType;

	/** To be set during generation */
	protected Label lReturn;

	protected RoutineStmt(StructuredSleigh ctx, String name, DataType retType, Runnable body) {
		super(ctx, body);
		this.name = name;
		this.retType = retType;
	}

	@Override
	protected StringTree generate(Label next, Label fall) {
		if (children.isEmpty()) {
			return StringTree.single("");
		}
		Label lExit = lReturn = next.freshOrBorrow();
		// This is an odd case, because it's the root: use lExit instead of fall
		StringTree blockGen = super.generate(lReturn, lExit);

		StringTree st = new StringTree();
		st.append(blockGen);
		st.append(lExit.genAnchor());
		return st;
	}
}
