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
package ghidra.pcode.emu.jit.gen.op;

import ghidra.pcode.emu.jit.op.JitIntXorOp;

/**
 * The generator for a {@link JitIntXorOp int_xor}.
 * 
 * <p>
 * This uses the bitwise binary operator and emits {@link #IXOR} or {@link #LXOR} depending on the
 * type.
 */
public enum IntXorOpGen implements BitwiseBinOpGen<JitIntXorOp> {
	/** The generator singleton */
	GEN;

	@Override
	public int intOpcode() {
		return IXOR;
	}

	@Override
	public int longOpcode() {
		return LXOR;
	}
}
