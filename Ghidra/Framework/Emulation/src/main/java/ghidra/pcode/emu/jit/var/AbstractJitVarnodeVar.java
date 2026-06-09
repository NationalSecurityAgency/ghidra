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

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.Varnode;

/**
 * An abstract implementation of {@link JitVarnodeVar}.
 */
public abstract class AbstractJitVarnodeVar extends AbstractJitVar implements JitVarnodeVar {
	protected final Varnode varnode;

	/**
	 * Construct a variable.
	 * 
	 * @param id the unique id
	 * @param varnode the varnode
	 */
	public AbstractJitVarnodeVar(int id, Varnode varnode) {
		super(id, varnode.getSize());
		if (varnode.getSize() < 1) {
			throw new IllegalArgumentException("Varnode must have size at least 1");
		}
		this.varnode = varnode;
	}

	@Override
	public Varnode varnode() {
		return varnode;
	}

	@Override
	public AddressSpace space() {
		return varnode.getAddress().getAddressSpace();
	}

	@Override
	public String toString() {
		return "%s[id=%d,varnode=%s]".formatted(getClass().getSimpleName(), id, varnode);
	}
}
