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

import ghidra.pcode.emu.jit.analysis.JitTypeBehavior;
import ghidra.pcode.emu.jit.var.JitVal;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;

/**
 * The use-def node for a {@link PcodeOp#STORE}.
 * 
 * @param op the p-code op
 * @param space the address space
 * @param offset the use-def node for the offset
 * @param value the use-def node for the value to store
 */
public record JitStoreOp(PcodeOp op, AddressSpace space, JitVal offset, JitVal value)
		implements JitOp {

	@Override
	public boolean canBeRemoved() {
		return false;
	}

	@Override
	public void link() {
		offset.addUse(this, 0);
		value.addUse(this, 1);
	}

	@Override
	public void unlink() {
		offset.removeUse(this, 0);
		value.removeUse(this, 1);
	}

	@Override
	public List<JitVal> inputs() {
		return List.of(offset, value);
	}

	@Override
	public JitTypeBehavior typeFor(int position) {
		return switch (position) {
			case 0 -> offsetType();
			case 1 -> valueType();
			default -> throw new AssertionError();
		};
	}

	/**
	 * We'd like the offset to be an {@link JitTypeBehavior#INTEGER int}.
	 * 
	 * @return {@link JitTypeBehavior#INTEGER}
	 */
	public JitTypeBehavior offsetType() {
		return JitTypeBehavior.INTEGER;
	}

	/**
	 * We do not require a particular type for the value.
	 * 
	 * @return {@link JitTypeBehavior#ANY}
	 */
	public JitTypeBehavior valueType() {
		return JitTypeBehavior.ANY;
	}
}
