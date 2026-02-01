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
package ghidra.pcode.emu.jit.var;

import java.util.List;

import ghidra.pcode.emu.jit.analysis.JitDataFlowArithmetic;
import ghidra.pcode.emu.jit.analysis.JitDataFlowState;
import ghidra.pcode.emu.jit.op.JitLoadOp;
import ghidra.pcode.emu.jit.op.JitOp;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;

/**
 * A dummy variable node representing an indirect memory access.
 * 
 * <p>
 * These are caused by {@link PcodeOp#LOAD}, since that is the only manner in which the
 * {@link JitDataFlowState} can be accessed with a non-constant offset. However, the node is
 * immediately dropped on the floor by
 * {@link JitDataFlowArithmetic#modAfterLoad(PcodeOp, AddressSpace, JitVal, JitVal)}, which instead
 * places the {@link JitLoadOp} into the use-def graph. This just exists so we don't return
 * {@code null}.
 */
public enum JitIndirectMemoryVar implements JitMemoryVar {
	/** Singleton */
	INSTANCE;

	@Override
	public int size() {
		return 0;
	}

	@Override
	public List<ValUse> uses() {
		return List.of();
	}

	@Override
	public void addUse(JitOp op, int position) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeUse(JitOp op, int position) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int id() {
		return -1;
	}

	@Override
	public AddressSpace space() {
		return null;
	}
}
