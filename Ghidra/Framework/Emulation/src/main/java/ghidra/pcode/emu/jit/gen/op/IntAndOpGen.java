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

import ghidra.pcode.emu.jit.op.JitIntAndOp;

/**
 * The generator for a {@link JitIntAndOp int_and}.
 * 
 * <p>
 * This uses the bitwise binary operator and emits {@link #IAND} or {@link #LAND} depending on the
 * type.
 */
public enum IntAndOpGen implements BitwiseBinOpGen<JitIntAndOp> {
	/** The generator singleton */
	GEN;

	@Override
	public int intOpcode() {
		return IAND;
	}

	@Override
	public int longOpcode() {
		return LAND;
	}
}
