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

import ghidra.pcode.emu.jit.analysis.JitType.LongJitType;
import ghidra.pcode.emu.jit.analysis.JitType.SimpleJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.Opnd;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.*;

/**
 * A handler for a p-code variable stored in part of a JVM {@code long}.
 * 
 * @param <ST> the JVM type of the sub variable
 * @param <SJT> the p-code type of the sub variable
 */
public interface SubInLongHandler<ST extends BPrim<?>, SJT extends SimpleJitType<ST, SJT>>
		extends SubVarHandler<ST, SJT, TLong, LongJitType> {

	@Override
	default <N extends Next> Emitter<Ent<N, TInt>> genLoadToBool(Emitter<N> em,
			JitCodeGenerator<?> gen) {
		long mask = longMask();
		return em
				.emit(Op::lload, local().local())
				.emit(Op::ldc__l, mask)
				.emit(Op::land)
				.emit(Op::ldc__l, 0)
				.emit(Op::lcmp);
	}

	@Override
	default <FT extends BPrim<?>, FJT extends SimpleJitType<FT, FJT>, N1 extends Next,
		N0 extends Ent<N1, FT>> Emitter<N1> genStoreFromStack(Emitter<N0> em,
				JitCodeGenerator<?> gen, FJT type, Ext ext, Scope scope) {
		long mask = longMask();
		return em
				.emit(Opnd::convert, type, LongJitType.I8, ext)
				.emit(Op::ldc__i, bitShift())
				.emit(Op::lshl)
				.emit(Op::ldc__l, mask)
				.emit(Op::land)
				.emit(Op::lload, local().local())
				.emit(Op::ldc__l, ~mask)
				.emit(Op::land)
				.emit(Op::lor)
				.emit(Op::lstore, local().local());
	}
}
