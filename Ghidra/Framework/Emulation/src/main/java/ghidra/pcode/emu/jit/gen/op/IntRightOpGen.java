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

import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.op.JitIntRightOp;

/**
 * The generator for a {@link JitIntRightOp int_right}.
 * 
 * <p>
 * This uses the integer shift operator generator and simply invokes
 * {@link JitCompiledPassage#intRight(int, int)}, etc. depending on the types.
 */
public enum IntRightOpGen implements ShiftIntBinOpGen<JitIntRightOp> {
	/** The generator singleton */
	GEN;

	@Override
	public String methodName() {
		return "intRight";
	}
}
