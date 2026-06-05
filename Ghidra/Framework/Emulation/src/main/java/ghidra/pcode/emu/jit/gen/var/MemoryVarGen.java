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
package ghidra.pcode.emu.jit.gen.var;

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorState;
import ghidra.pcode.emu.jit.analysis.JitDataFlowArithmetic;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.access.AccessGen;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.OpndEm;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.var.JitVarnodeVar;
import ghidra.program.model.pcode.Varnode;

/**
 * The generator for memory variables.
 * 
 * <p>
 * These variables affect the {@link JitBytesPcodeExecutorState state} immediately, i.e., they are
 * not birthed or retired as local JVM variables. The generator delegates to the appropriate
 * {@link AccessGen} for this variable's varnode and assigned type.
 * 
 * @param <V> the class of p-code variable node in the use-def graph
 */
public interface MemoryVarGen<V extends JitVarnodeVar> extends VarGen<V> {

	/**
	 * Get the varnode actually accessed for the given p-code variable
	 * <p>
	 * This is made to be overridden for the implementation of subpiece access.
	 * 
	 * @param gen the code generator
	 * @param v the value
	 * @return the varnode
	 */
	default Varnode getVarnode(JitCodeGenerator<?> gen, V v) {
		return v.varnode();
	}

	@Override
	default <THIS extends JitCompiledPassage, N extends Next> Emitter<N> genValInit(Emitter<N> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, V v) {
		return VarGen.genVarnodeInit(em, gen, getVarnode(gen, v));
	}

	@Override
	default <THIS extends JitCompiledPassage, T extends BPrim<?>, JT extends SimpleJitType<T, JT>,
		N extends Next> Emitter<Ent<N, T>> genReadToStack(Emitter<N> em,
				Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, V v, JT type, Ext ext) {
		return VarGen.genReadValDirectToStack(em, localThis, gen, type, getVarnode(gen, v));
	}

	@Override
	default <THIS extends JitCompiledPassage, N extends Next> OpndEm<MpIntJitType, N> genReadToOpnd(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, V v,
			MpIntJitType type, Ext ext, Scope scope) {
		return AccessGen.lookupMp(gen.getAnalysisContext().getEndian())
				.genReadToOpnd(em, localThis, gen, getVarnode(gen, v), type, ext, scope);
	}

	@Override
	default <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TInt>>
			genReadLegToStack(Emitter<N> em, Local<TRef<THIS>> localThis,
					JitCodeGenerator<THIS> gen, V v, MpIntJitType type, int leg, Ext ext) {
		Varnode vn = getVarnode(gen, v);
		if (vn.getSize() <= leg * Integer.BYTES) {
			return switch (ext) {
				case ZERO -> em
						.emit(Op::ldc__i, 0);
				case SIGN -> {
					Varnode msbVn = switch (gen.getAnalysisContext().getEndian()) {
						case BIG -> new Varnode(vn.getAddress(), 1);
						case LITTLE -> new Varnode(vn.getAddress().add(vn.getSize() - 1), 1);
					};
					yield em
							.emit(VarGen::genReadValDirectToStack, localThis, gen, IntJitType.I1,
								msbVn)
							.emit(Op::ldc__i, Integer.SIZE - Byte.SIZE)
							.emit(Op::ishl)
							.emit(Op::ldc__i, Integer.SIZE - 1)
							.emit(Op::ishr);
				}
			};
		}
		Varnode subVn = JitDataFlowArithmetic.subPieceVn(gen.getAnalysisContext().getEndian(), vn,
			leg * Integer.BYTES, Integer.BYTES);
		return VarGen.genReadValDirectToStack(em, localThis, gen, type.legTypesLE().get(leg),
			subVn);
	}

	@Override
	default <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TRef<int[]>>>
			genReadToArray(Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen,
					V v, MpIntJitType type, Ext ext, Scope scope, int slack) {
		return AccessGen.lookupMp(gen.getAnalysisContext().getEndian())
				.genReadToArray(em, localThis, gen, getVarnode(gen, v), type, ext, scope, slack);
	}

	@Override
	default <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TInt>> genReadToBool(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, V v) {
		return AccessGen.genReadToBool(em, localThis, gen, getVarnode(gen, v));
	}
}
