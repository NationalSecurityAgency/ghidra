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
package ghidra.pcode.opbehavior;

import ghidra.program.model.pcode.PcodeOp;

public enum SpecialOpBehavior implements OpBehavior {
	OP_LOAD(PcodeOp.LOAD),
	OP_STORE(PcodeOp.STORE),
	OP_BRANCH(PcodeOp.BRANCH),
	OP_CBRANCH(PcodeOp.CBRANCH),
	OP_BRANCHIND(PcodeOp.BRANCHIND),
	OP_CALL(PcodeOp.CALL),
	OP_CALLIND(PcodeOp.CALLIND),
	OP_CALLOTHER(PcodeOp.CALLOTHER),
	OP_RETURN(PcodeOp.RETURN),

	OP_MULTIEQUAL(PcodeOp.MULTIEQUAL),
	OP_INDIRECT(PcodeOp.INDIRECT),

	OP_CAST(PcodeOp.CAST),
	OP_PTRADD(PcodeOp.PTRADD),
	OP_PTRSUB(PcodeOp.PTRSUB),

	OP_SEGMENTOP(PcodeOp.SEGMENTOP),
	OP_CPOOLREF(PcodeOp.CPOOLREF),
	OP_NEW(PcodeOp.NEW),
	OP_INSERT(PcodeOp.INSERT),
	OP_ZPULL(PcodeOp.ZPULL),
	OP_SPULL(PcodeOp.SPULL);

	private final int opcode;

	SpecialOpBehavior(int opcode) {
		this.opcode = opcode;
	}

	@Override
	public int opcode() {
		return opcode;
	}
}
