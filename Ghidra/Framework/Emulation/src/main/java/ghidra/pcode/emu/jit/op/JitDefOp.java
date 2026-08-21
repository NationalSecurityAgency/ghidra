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

import ghidra.pcode.emu.jit.analysis.JitTypeBehavior;
import ghidra.pcode.emu.jit.var.JitOutVar;
import ghidra.program.model.address.AddressSpace;

/**
 * A p-code operator use-def node with an output
 */
public interface JitDefOp extends JitOp {
	@Override
	default boolean canBeRemoved() {
		AddressSpace space = out().varnode().getAddress().getAddressSpace();
		return space.isUniqueSpace() || space.isRegisterSpace();
	}

	/**
	 * The the use-def variable node for the output.
	 * 
	 * @return the output
	 */
	JitOutVar out();

	@Override
	default void link() {
		out().setDefinition(this);
	}

	@Override
	default void unlink() {
		if (out().definition() == this) {
			out().setDefinition(null);
		}
	}

	/**
	 * The required type behavior for the output
	 * 
	 * @return the behavior
	 */
	JitTypeBehavior type();
}
