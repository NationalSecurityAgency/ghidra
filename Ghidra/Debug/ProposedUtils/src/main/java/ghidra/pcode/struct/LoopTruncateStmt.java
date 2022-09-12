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
import ghidra.pcode.struct.StructuredSleigh.StructuredSleighError;

abstract class LoopTruncateStmt extends AbstractStmt {
	protected LoopTruncateStmt(StructuredSleigh ctx) {
		super(ctx);
	}

	protected LoopStmt getContainingLoop() {
		LoopStmt loop = nearest(LoopStmt.class);
		if (loop == null) {
			throw new StructuredSleighError("No loop to break or continue");
		}
		return loop;
	}

	@Override
	protected StringTree generate(Label next, Label fall) {
		return getNext().genGoto(fall);
	}

	@Override
	protected boolean isSingleGoto() {
		return true;
	}
}
