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
package ghidra.pcode.emu.jit.gen.access;

import static ghidra.pcode.emu.jit.gen.GenConsts.BLOCK_SIZE;

import java.util.ArrayList;
import java.util.List;

import ghidra.pcode.emu.jit.analysis.JitType.IntJitType;
import ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.*;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.*;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.Varnode;

/**
 * The generator for writing multi-precision ints.
 */
public enum MpIntAccessGen implements MpAccessGen {
	/** The big-endian instance */
	BE(IntAccessGen.BE) {
		@Override
		protected List<IntJitType> orderedLegTypes(MpIntJitType type) {
			return type.legTypesBE();
		}

		@Override
		protected List<SimpleOpnd<TInt, IntJitType>> orderedLegs(Opnd<MpIntJitType> opnd) {
			return opnd.type().castLegsLE(opnd).reversed();
		}
	},
	/** The little-endian instance */
	LE(IntAccessGen.LE) {
		@Override
		protected List<IntJitType> orderedLegTypes(MpIntJitType type) {
			return type.legTypesLE();
		}

		@Override
		protected List<SimpleOpnd<TInt, IntJitType>> orderedLegs(Opnd<MpIntJitType> opnd) {
			return opnd.type().castLegsLE(opnd);
		}
	};

	final IntAccessGen legGen;

	private MpIntAccessGen(IntAccessGen legGen) {
		this.legGen = legGen;
	}

	/**
	 * Arrange the leg types so that the least-significant one is first
	 * 
	 * @param type the mp-int type
	 * @return the leg types in little-endian order
	 */
	protected abstract List<IntJitType> orderedLegTypes(MpIntJitType type);

	/**
	 * Arrange the operand legs so that the least-significant one is first
	 * 
	 * @param opnd the mp-int operand
	 * @return the legs in little-endian order
	 */
	protected abstract List<SimpleOpnd<TInt, IntJitType>> orderedLegs(Opnd<MpIntJitType> opnd);

	@Override
	public <THIS extends JitCompiledPassage, N extends Next> OpndEm<MpIntJitType, N> genReadToOpnd(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, Varnode vn,
			MpIntJitType type, Ext ext, Scope scope) {
		AddressSpace space = vn.getAddress().getAddressSpace();
		List<SimpleOpnd<TInt, IntJitType>> legs = new ArrayList<>();
		MpIntJitType fromType = MpIntJitType.forSize(vn.getSize());
		long offset = vn.getOffset();
		for (IntJitType t : orderedLegTypes(fromType)) {
			long block = offset / BLOCK_SIZE * BLOCK_SIZE;
			int off = (int) (offset - block);
			String name = "mpl_%s_%x_%d_leg%x".formatted(space.getName(), vn.getOffset(),
				vn.getSize(), offset);
			int legSize = t.size();
			var result = em
					.emit(legGen::genReadLegToStack, localThis, gen, space, block, off, legSize)
					.emit(Opnd::createInt, t, name, scope);
			legs.add(result.opnd());
			em = result.em();
			offset += legSize;
		}
		MpIntLocalOpnd temp = MpIntLocalOpnd.of(fromType,
			"mem_%s_%x_%d".formatted(space.getName(), vn.getOffset(), vn.getSize()), legs);
		return MpIntToMpInt.INSTANCE.convertOpndToOpnd(em, temp, type, ext, scope);
	}

	@Override
	public <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TRef<int[]>>>
			genReadToArray(Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen,
					Varnode vn, MpIntJitType type, Ext ext, Scope scope, int slack) {
		AddressSpace space = vn.getAddress().getAddressSpace();
		Local<TRef<int[]>> arr = scope.decl(Types.T_INT_ARR,
			"mpa_mem_%s_%x_%d".formatted(space.getName(), vn.getOffset(), vn.getSize()));
		List<IntJitType> fromLegTypes = orderedLegTypes(MpIntJitType.forSize(vn.getSize()));
		List<IntJitType> toLegTypes = orderedLegTypes(type);
		int legsOut = toLegTypes.size();
		int legsIn = fromLegTypes.size();
		int defLegs = Integer.min(legsIn, legsOut);
		em = em
				.emit(Op::ldc__i, defLegs + slack)
				.emit(Op::newarray, Types.T_INT)
				.emit(Op::astore, arr);
		long offset = vn.getOffset();
		for (int i = 0; i < defLegs; i++) {
			IntJitType fromLegType = fromLegTypes.get(i);
			IntJitType toLegType = toLegTypes.get(i);
			long block = offset / BLOCK_SIZE * BLOCK_SIZE;
			int off = (int) (offset - block);
			int legSize = fromLegType.size();
			em = em
					.emit(Op::aload, arr)
					.emit(Op::ldc__i, i)
					.emit(legGen::genReadLegToStack, localThis, gen, space, block, off, legSize)
					.emit(Opnd::convertIntToInt, fromLegType, toLegType, ext)
					.emit(Op::iastore);
			offset += legSize;
		}
		return em
				.emit(MpIntToMpInt::doGenArrExt, arr, legsOut, defLegs, ext, scope)
				.emit(Op::aload, arr);
	}

	@Override
	public <THIS extends JitCompiledPassage, N extends Next> Emitter<N> genWriteFromOpnd(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen,
			Opnd<MpIntJitType> opnd, Varnode vn) {
		AddressSpace space = vn.getAddress().getAddressSpace();
		long offset = vn.getOffset();
		for (SimpleOpnd<TInt, IntJitType> leg : orderedLegs(opnd)) {
			long block = offset / BLOCK_SIZE * BLOCK_SIZE;
			int off = (int) (offset - block);
			int legSize = leg.type().size();
			em = em
					.emit(leg::read)
					.emit(legGen::genWriteLegFromStack, localThis, gen, space, block, off, legSize);
			offset += legSize;
		}
		return em;
	}

	@Override
	public <THIS extends JitCompiledPassage, N1 extends Next, N0 extends Ent<N1, TRef<int[]>>>
			Emitter<N1> genWriteFromArray(Emitter<N0> em, Local<TRef<THIS>> localThis,
					JitCodeGenerator<THIS> gen, Varnode vn, Scope scope) {
		AddressSpace space = vn.getAddress().getAddressSpace();
		Local<TRef<int[]>> arr = scope.decl(Types.T_INT_ARR,
			"mpa_mem_%s_%x_%d".formatted(space.getName(), vn.getOffset(), vn.getSize()));
		var em1 = em
				.emit(Op::astore, arr);
		List<IntJitType> legTypes = orderedLegTypes(MpIntJitType.forSize(vn.getSize()));
		final int legCount = legTypes.size();
		long offset = vn.getOffset();
		for (int i = 0; i < legCount; i++) {
			IntJitType t = legTypes.get(i);
			long block = offset / BLOCK_SIZE * BLOCK_SIZE;
			int off = (int) (offset - block);
			int legSize = t.size();
			em1 = em1
					.emit(Op::aload, arr)
					.emit(Op::ldc__i, i)
					.emit(Op::iaload)
					.emit(legGen::genWriteLegFromStack, localThis, gen, space, block, off, legSize);
			offset += legSize;
		}
		return em1;
	}
}
