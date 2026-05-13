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

import org.objectweb.asm.Opcodes;

import ghidra.pcode.emu.jit.alloc.VarHandler;
import ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType;
import ghidra.pcode.emu.jit.analysis.JitType.SimpleJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.OpndEm;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.var.JitVarnodeVar;

/**
 * The generator for local variable access.
 * 
 * <p>
 * These variables are presumed to be allocated as JVM locals. The generator emits
 * {@link Opcodes#ILOAD iload} and {@link Opcodes#ISTORE istore} and or depending on the assigned
 * type.
 * 
 * @param <V> the class of p-code variable node in the use-def graph
 */
public interface LocalVarGen<V extends JitVarnodeVar> extends VarGen<V> {

	/**
	 * Get the handler for a given p-code variable
	 * <p>
	 * This is made to be overridden for the implementation of subpiece handlers.
	 * 
	 * @param gen the code generator
	 * @param v the value
	 * @return the handler
	 */
	default VarHandler getHandler(JitCodeGenerator<?> gen, V v) {
		return gen.getAllocationModel().getHandler(v);
	}

	@Override
	default <THIS extends JitCompiledPassage, N extends Next> Emitter<N> genValInit(Emitter<N> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, V v) {
		return em;
	}

	@Override
	default <THIS extends JitCompiledPassage, T extends BPrim<?>, JT extends SimpleJitType<T, JT>,
		N extends Next> Emitter<Ent<N, T>> genReadToStack(Emitter<N> em,
				Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, V v, JT type, Ext ext) {
		return getHandler(gen, v).genLoadToStack(em, gen, type, ext);
	}

	@Override
	default <THIS extends JitCompiledPassage, N extends Next> OpndEm<MpIntJitType, N> genReadToOpnd(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, V v,
			MpIntJitType type, Ext ext, Scope scope) {
		return getHandler(gen, v).genLoadToOpnd(em, gen, type, ext, scope);
	}

	@Override
	default <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TInt>>
			genReadLegToStack(Emitter<N> em, Local<TRef<THIS>> localThis,
					JitCodeGenerator<THIS> gen, V v, MpIntJitType type, int leg, Ext ext) {
		return getHandler(gen, v).genLoadLegToStack(em, gen, type, leg, ext);
	}

	@Override
	default <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TRef<int[]>>>
			genReadToArray(Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen,
					V v, MpIntJitType type, Ext ext, Scope scope, int slack) {
		return getHandler(gen, v).genLoadToArray(em, gen, type, ext, scope, slack);
	}

	@Override
	default <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TInt>> genReadToBool(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, V v) {
		return getHandler(gen, v).genLoadToBool(em, gen);
	}
}
