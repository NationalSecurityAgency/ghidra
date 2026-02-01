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
package ghidra.pcode.emu.jit.op;

import java.util.List;

import ghidra.pcode.emu.jit.JitPassage.RIndBranch;
import ghidra.pcode.emu.jit.analysis.JitTypeBehavior;
import ghidra.pcode.emu.jit.var.JitVal;
import ghidra.program.model.pcode.PcodeOp;

/**
 * The use-def node for a {@link PcodeOp#BRANCHIND}.
 * 
 * @param op the p-code op
 * @param target the use-def node for the target offset
 * @param branch the branch record created for the p-code op
 */
public record JitBranchIndOp(PcodeOp op, JitVal target, RIndBranch branch) implements JitOp {

	@Override
	public boolean canBeRemoved() {
		return false;
	}

	@Override
	public void link() {
		target.addUse(this, 0);
	}

	@Override
	public void unlink() {
		target.removeUse(this, 0);
	}

	@Override
	public List<JitVal> inputs() {
		return List.of(target);
	}

	@Override
	public JitTypeBehavior typeFor(int position) {
		return switch (position) {
			case 0 -> targetType();
			default -> throw new AssertionError();
		};
	}

	/**
	 * We'd like the offset to be an {@link JitTypeBehavior#INTEGER int}.
	 * 
	 * @return {@link JitTypeBehavior#INTEGER}
	 */
	public JitTypeBehavior targetType() {
		return JitTypeBehavior.INTEGER;
	}
}
