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
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.BPrim;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.pcode.Varnode;

/**
 * The handler for an {@link IntJitType int} p-code variable stored in part of a JVM {@code int}.
 * 
 * @param local see {@link #local()}
 * @param type see {@link #type()}
 * @param vn see {@link #vn()} (wrt. the sub variable)
 * @param byteShift see {@link #byteShift()}
 */
public record IntInIntHandler(JvmLocal<TInt, IntJitType> local, IntJitType type, Varnode vn,
		int byteShift) implements SubVarHandler<TInt, IntJitType, TInt, IntJitType> {

	@SuppressWarnings("javadoc")
	public IntInIntHandler {
		assertShiftFits(byteShift, type, local);
	}

	@Override
	public MpToStackConv<TInt, IntJitType, MpIntJitType, TInt, IntJitType> getConvToSub() {
		return MpIntToInt.INSTANCE;
	}

	@Override
	public <TT extends BPrim<?>, TJT extends SimpleJitType<TT, TJT>, N extends Next>
			Emitter<Ent<N, TT>>
			genLoadToStack(Emitter<N> em, JitCodeGenerator<?> gen, TJT type, Ext ext) {
		return em
				.emit(Op::iload, local.local())
				.emit(Op::ldc__i, bitShift())
				.emit(Op::iushr)
				.emit(Opnd::convert, this.type, type, ext);
	}

	@Override
	public <N extends Next> Emitter<Ent<N, TInt>> genLoadLegToStack(Emitter<N> em,
			JitCodeGenerator<?> gen, MpIntJitType type, int leg, Ext ext) {
		if (leg == 0) {
			return genLoadToStack(em, gen, type.legTypesLE().get(leg), ext);
		}
		return switch (ext) {
			case ZERO -> em
					.emit(Op::ldc__i, 0);
			case SIGN -> {
				int msb = (this.type.size() + byteShift) * Byte.SIZE;
				if (msb == Integer.SIZE) {
					yield em
							.emit(Op::iload, local.local())
							.emit(Op::ldc__i, Integer.SIZE - 1)
							.emit(Op::ishr);
				}
				yield em
						.emit(Op::iload, local.local())
						.emit(Op::ldc__i, Integer.SIZE - msb)
						.emit(Op::ishl)
						.emit(Op::ldc__i, Integer.SIZE - 1)
						.emit(Op::ishr);
			}
		};
	}

	@Override
	public <N extends Next> Emitter<Ent<N, TInt>> genLoadToBool(Emitter<N> em,
			JitCodeGenerator<?> gen) {
		int mask = intMask();
		return em
				.emit(Op::iload, local.local())
				.emit(Op::ldc__i, mask)
				.emit(Op::iand)
				.emit(Opnd::intToBool);
	}

	@Override
	public <FT extends BPrim<?>, FJT extends SimpleJitType<FT, FJT>, N1 extends Next,
		N0 extends Ent<N1, FT>> Emitter<N1> genStoreFromStack(Emitter<N0> em,
				JitCodeGenerator<?> gen, FJT type, Ext ext, Scope scope) {
		int mask = intMask();
		return em
				.emit(Opnd::convert, type, local.type(), ext)
				.emit(Op::ldc__i, bitShift())
				.emit(Op::ishl)
				.emit(Op::ldc__i, mask)
				.emit(Op::iand)
				.emit(Op::iload, local.local())
				.emit(Op::ldc__i, ~mask)
				.emit(Op::iand)
				.emit(Op::ior)
				.emit(Op::istore, local.local());
	}

	@Override
	public VarHandler subpiece(Endian endian, int byteOffset, int maxByteSize) {
		Varnode subVn = JitDataFlowArithmetic.subPieceVn(endian, vn, byteOffset, maxByteSize);
		return new IntInIntHandler(local, IntJitType.forSize(subVn.getSize()), subVn,
			byteShift + byteOffset);
	}
}
