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

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.type.TypeConversions;
import ghidra.pcode.emu.jit.op.JitIntSRightOp;

/**
 * The generator for a {@link JitIntSRightOp int_sright}.
 * 
 * <p>
 * This uses the integer shift operator generator and simply invokes
 * {@link JitCompiledPassage#intSRight(int, int)}, etc. depending on the types.
 */
public enum IntSRightOpGen implements ShiftIntBinOpGen<JitIntSRightOp> {
	/** The generator singleton */
	GEN;

	@Override
	public String methodName() {
		return "intSRight";
	}

	@Override
	public JitType afterLeft(JitCodeGenerator gen, JitIntSRightOp op, JitType lType, JitType rType,
			MethodVisitor rv) {
		TypeConversions.generateSExt(lType, rv);
		return lType;
	}
}
