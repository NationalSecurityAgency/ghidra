/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.model.block;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

/**
 * This BlockModel implements the Basic block model.
 *
 * Each Codeblock is made up of contiguous instructions in address order.
 *
 *  Blocks satisfy the following:<ol>
 *   <li>Any instruction with a label starts a block.
 *   <li>Each instruction that could cause program control flow to change local to 
 *       the containing function (i.e., excludes calls) is the last instruction of a Codeblock.
 *   <li>All other instructions are "NOP" fallthroughs, meaning
 *      after execution the program counter will be at
 *      the instruction immediately following.
 *   <li>Any instruction that is unreachable and has no label is also considered the start
 *       of a block.
 * </ol>
 * So a CodeBlock in this model consists of contiguous code that has zero or
 * more fallthrough or call instructions followed by a single flow instruction.
 * Each block may or may not have a label at the first instruction, but may not
 * have a label at any other instruction contained in the block.
 * 
 * This model handles delay slot instructions with the following 
 * assumptions:<ol>
 * <li>The delay slot depth of the delayed instruction will always
 *     correspond to the number of delay slot instructions immediately
 *     following the instruction. The model may not behave properly if
 *     the disassembled code violates this assumption.
 * </ol>
 * @see ghidra.program.model.block.CodeBlockModel
 */
public class BasicBlockModel extends SimpleBlockModel {

	public static final String NAME = "Basic Block";

	public BasicBlockModel(Program program) {
		super(program);
	}

	public BasicBlockModel(Program program, boolean includeExternals) {
		super(program, includeExternals);
	}

	@Override
	protected boolean hasEndOfBlockFlow(Instruction instr) {
		FlowType flowType = instr.getFlowType();
		if (flowType.isJump() || flowType.isTerminal()) {
			return true;
		}
		for (Reference ref : instr.getReferencesFrom()) {
			RefType refType = ref.getReferenceType();
			if (refType.isJump() || refType.isTerminal()) {
				return true;
			}
		}
		return false;
	}

}
