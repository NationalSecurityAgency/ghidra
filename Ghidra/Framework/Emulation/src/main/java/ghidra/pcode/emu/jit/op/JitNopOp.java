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

import ghidra.pcode.emu.jit.JitPassage.NopPcodeOp;
import ghidra.pcode.emu.jit.analysis.JitTypeBehavior;
import ghidra.pcode.emu.jit.var.JitVal;
import ghidra.program.model.pcode.PcodeOp;

/**
 * The use-def node for a {@link NopPcodeOp} or an inlined {@link PcodeOp#CALLOTHER}.
 * 
 * <p>
 * When a callother is inlined, we preserve the original op for bookkeeping, but ensure that no code
 * is emitted for it by wrapping it in this use-def node class.
 * 
 * @param op the p-code op
 */
public record JitNopOp(PcodeOp op) implements JitOp {

	@Override
	public boolean canBeRemoved() {
		return true;
	}

	@Override
	public void link() {
		// Nothing
	}

	@Override
	public void unlink() {
		// Nothing
	}

	@Override
	public List<JitVal> inputs() {
		return List.of();
	}

	@Override
	public JitTypeBehavior typeFor(int position) {
		throw new AssertionError();
	}
}
