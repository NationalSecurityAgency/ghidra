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
import ghidra.pcode.emu.jit.analysis.JitType.IntJitType;
import ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.Opnd;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.*;
import ghidra.pcode.emu.jit.gen.util.Emitter;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Scope;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.pcode.Varnode;

/**
 * The handler for a p-code variable allocated in one JVM {@code int}.
 * 
 * @param local the JVM local
 * @param type the p-code type
 */
public record IntVarAlloc(JvmLocal<TInt, IntJitType> local, IntJitType type)
		implements SimpleVarHandler<TInt, IntJitType> {

	@Override
	public <N extends Next> Emitter<Ent<N, TInt>> genLoadLegToStack(Emitter<N> em,
			JitCodeGenerator<?> gen, MpIntJitType type, int leg, Ext ext) {
		return genLoadLegToStackC1(em, gen, type, leg, ext);
	}

	@Override
	public <N extends Next> OpndEm<MpIntJitType, N> genLoadToOpnd(Emitter<N> em,
			JitCodeGenerator<?> gen, MpIntJitType type, Ext ext, Scope scope) {
		return IntToMpInt.INSTANCE.doConvert(em, local.opnd(), local.name(), type, ext, scope);
	}

	@Override
	public MpToStackConv<TInt, IntJitType, MpIntJitType, TInt, IntJitType> getConvToStack() {
		return MpIntToInt.INSTANCE;
	}

	@Override
	public <N extends Next> Emitter<Ent<N, TInt>> genLoadToBool(Emitter<N> em,
			JitCodeGenerator<?> gen) {
		return em
				.emit(this::genLoadToStack, gen, type, Ext.ZERO)
				.emit(Opnd::intToBool);
	}

	@Override
	public VarHandler subpiece(Endian endian, int byteOffset, int maxByteSize) {
		Varnode subVn = JitDataFlowArithmetic.subPieceVn(endian, local.vn(), byteOffset,
			Math.min(type.size(), maxByteSize));
		if (byteOffset == 0) {
			return new IntVarAlloc(local, IntJitType.forSize(subVn.getSize()));
		}
		return new IntInIntHandler(local, IntJitType.forSize(subVn.getSize()), subVn, byteOffset);
	}
}
