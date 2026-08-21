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

import ghidra.pcode.emu.jit.op.JitOp;

/**
 * A value that is forbidden from being translated
 */
public enum JitFailVal implements JitVal {
	/** Singleton */
	INSTANCE;

	@Override
	public int size() {
		return 1;
	}

	@Override
	public List<ValUse> uses() {
		return List.of();
	}

	@Override
	public void addUse(JitOp op, int position) {
	}

	@Override
	public void removeUse(JitOp op, int position) {
	}
}
