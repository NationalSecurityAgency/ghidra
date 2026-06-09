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

import java.util.ArrayList;
import java.util.List;

import ghidra.pcode.emu.jit.op.JitOp;

/**
 * An abstract implementation of {@link JitVal}.
 */
public abstract class AbstractJitVal implements JitVal {
	protected final int size;
	protected final List<ValUse> uses = new ArrayList<>();

	/**
	 * Construct a value of the given size.
	 * 
	 * @param size the size in bytes
	 */
	public AbstractJitVal(int size) {
		this.size = size;
	}

	@Override
	public int size() {
		return size;
	}

	@Override
	public List<ValUse> uses() {
		return uses;
	}

	@Override
	public void addUse(JitOp op, int position) {
		uses.add(new ValUse(op, position));
	}

	@Override
	public void removeUse(JitOp op, int position) {
		uses.remove(new ValUse(op, position));
	}
}
