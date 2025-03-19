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

import ghidra.pcode.emu.jit.op.JitIntNotEqualOp;

/**
 * The generator for a {@link JitIntNotEqualOp int_notequal}.
 * 
 * <p>
 * This uses the integer comparison operator generator and simply emits {@link #IF_ICMPNE} or
 * {@link #IFNE} depending on the type.
 */
public enum IntNotEqualOpGen implements CompareIntBinOpGen<JitIntNotEqualOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return true; // Doesn't matter. Java favors signed.
	}

	@Override
	public int icmpOpcode() {
		return IF_ICMPNE;
	}

	@Override
	public int ifOpcode() {
		return IFNE;
	}
}
