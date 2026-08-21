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

import ghidra.pcode.emu.jit.analysis.JitDataFlowArithmetic;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.Opnd;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.*;
import ghidra.pcode.emu.jit.gen.util.Emitter;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Op;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.pcode.Varnode;

/**
 * The handler for an {@link LongJitType long} p-code variable stored in part of a JVM {@code long}.
 * 
 * @param local see {@link #local()}
 * @param type see {@link #type()}
 * @param vn see {@link #vn()} (wrt. the sub variable)
 * @param byteShift see {@link #byteShift()}
 */
public record LongInLongHandler(JvmLocal<TLong, LongJitType> local, LongJitType type, Varnode vn,
		int byteShift) implements SubInLongHandler<TLong, LongJitType> {

	@SuppressWarnings("javadoc")
	public LongInLongHandler {
		assertShiftFits(byteShift, type, local);
	}

	@Override
	public MpToStackConv<TInt, IntJitType, MpIntJitType, TLong, LongJitType> getConvToSub() {
		return MpIntToLong.INSTANCE;
	}

	@Override
	public <TT extends BPrim<?>, TJT extends SimpleJitType<TT, TJT>, N extends Next>
			Emitter<Ent<N, TT>>
			genLoadToStack(Emitter<N> em, JitCodeGenerator<?> gen, TJT type, Ext ext) {
		return em
				.emit(Op::lload, local.local())
				.emit(Op::ldc__i, bitShift())
				.emit(Op::lushr)
				.emit(Opnd::convert, this.type, type, ext);
	}

	@Override
	public <N extends Next> Emitter<Ent<N, TInt>> genLoadLegToStack(Emitter<N> em,
			JitCodeGenerator<?> gen, MpIntJitType type, int leg, Ext ext) {
		if (leg == 0) {
			Varnode subVn = JitDataFlowArithmetic.subPieceVn(gen.getAnalysisContext().getEndian(),
				vn, 0, Integer.BYTES);
			return new IntInLongHandler(local, IntJitType.I4, subVn, byteShift)
					.genLoadLegToStack(em, gen, type, leg, ext);
		}
		Varnode subVn = JitDataFlowArithmetic.subPieceVn(gen.getAnalysisContext().getEndian(),
			vn, Integer.BYTES, vn.getSize() - Integer.BYTES);
		return new IntInLongHandler(local, IntJitType.forSize(subVn.getSize()), subVn,
			byteShift + Integer.BYTES).genLoadLegToStack(em, gen, type, leg - 1, ext);
	}

	@Override
	public VarHandler subpiece(Endian endian, int byteOffset, int maxByteSize) {
		Varnode subVn = JitDataFlowArithmetic.subPieceVn(endian, vn, byteOffset, maxByteSize);
		if (subVn.getSize() <= Integer.BYTES) {
			return new IntInLongHandler(local, IntJitType.forSize(subVn.getSize()), subVn,
				byteShift + byteOffset);
		}
		return new LongInLongHandler(local, LongJitType.forSize(subVn.getSize()), subVn,
			byteShift + byteOffset);
	}
}
