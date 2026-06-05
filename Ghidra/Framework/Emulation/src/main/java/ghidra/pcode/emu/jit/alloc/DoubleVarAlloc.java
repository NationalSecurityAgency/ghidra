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
package ghidra.pcode.emu.jit.alloc;

import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.MpToStackConv;
import ghidra.pcode.emu.jit.gen.util.Emitter;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Op;
import ghidra.pcode.emu.jit.gen.util.Types.TDouble;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;
import ghidra.program.model.lang.Endian;

/**
 * The handler for a p-code variable allocated in one JVM {@code double}.
 * 
 * @param local the JVM local
 * @param type the p-code type
 */
public record DoubleVarAlloc(JvmLocal<TDouble, DoubleJitType> local, DoubleJitType type)
		implements SimpleVarHandler<TDouble, DoubleJitType> {

	@Override
	public <N extends Next> Emitter<Ent<N, TInt>> genLoadLegToStack(Emitter<N> em,
			JitCodeGenerator<?> gen, MpIntJitType type, int leg, Ext ext) {
		return genLoadLegToStackC2(em, gen, type, leg, ext);
	}

	@Override
	public MpToStackConv<TInt, IntJitType, MpIntJitType, TDouble, DoubleJitType> getConvToStack() {
		throw new AssertionError();
	}

	@Override
	public <N extends Next> Emitter<Ent<N, TInt>> genLoadToBool(Emitter<N> em,
			JitCodeGenerator<?> gen) {
		return em
				.emit(this::genLoadToStack, gen, type, Ext.ZERO)
				.emit(Op::ldc__d, 0.0)
				.emit(Op::dcmpl); // So long as lsb is set, it's true
	}

	@Override
	public VarHandler subpiece(Endian endian, int byteOffset, int maxByteSize) {
		throw new AssertionError("Who's subpiecing a double?");
	}
}
