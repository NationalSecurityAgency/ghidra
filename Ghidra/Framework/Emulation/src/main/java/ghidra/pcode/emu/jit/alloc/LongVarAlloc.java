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
import ghidra.pcode.emu.jit.gen.opnd.Opnd.*;
import ghidra.pcode.emu.jit.gen.util.Emitter;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Op;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;
import ghidra.pcode.emu.jit.gen.util.Types.TLong;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.pcode.Varnode;

/**
 * The handler for a p-code variable allocated in one JVM {@code long}.
 * 
 * @param local the JVM local
 * @param type the p-code type
 */
public record LongVarAlloc(JvmLocal<TLong, LongJitType> local, LongJitType type)
		implements SimpleVarHandler<TLong, LongJitType> {

	@Override
	public <N extends Next> Emitter<Ent<N, TInt>> genLoadLegToStack(Emitter<N> em,
			JitCodeGenerator<?> gen, MpIntJitType type, int leg, Ext ext) {
		return genLoadLegToStackC2(em, gen, type, leg, ext);
	}

	@Override
	public MpToStackConv<TInt, IntJitType, MpIntJitType, TLong, LongJitType> getConvToStack() {
		return MpIntToLong.INSTANCE;
	}

	@Override
	public <N extends Next> Emitter<Ent<N, TInt>> genLoadToBool(Emitter<N> em,
			JitCodeGenerator<?> gen) {
		return em
				.emit(this::genLoadToStack, gen, type, Ext.ZERO)
				.emit(Op::ldc__l, 0)
				.emit(Op::lcmp); // Outputs -1, 0, or 1. So long as lsb is set, it's true.
	}

	@Override
	public VarHandler subpiece(Endian endian, int byteOffset, int maxByteSize) {
		Varnode subVn = JitDataFlowArithmetic.subPieceVn(endian, local.vn(), byteOffset,
			Math.min(type.size(), maxByteSize));
		if (byteOffset == 0) {
			return new LongVarAlloc(local, LongJitType.forSize(subVn.getSize()));
		}
		if (subVn.getSize() <= Integer.BYTES) {
			return new IntInLongHandler(local, IntJitType.forSize(subVn.getSize()), subVn,
				byteOffset);
		}
		return new LongInLongHandler(local, LongJitType.forSize(subVn.getSize()), subVn,
			byteOffset);
	}
}
