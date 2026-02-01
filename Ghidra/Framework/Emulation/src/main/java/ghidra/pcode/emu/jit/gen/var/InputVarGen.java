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

import ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType;
import ghidra.pcode.emu.jit.analysis.JitType.SimpleJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.Opnd;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.var.JitInputVar;

/**
 * The generator for a local variable that is input to the passage.
 * 
 * <p>
 * This prohibits generation of code to write the variable.
 */
public interface InputVarGen extends LocalVarGen<JitInputVar> {

	@Override
	default <THIS extends JitCompiledPassage, T extends BPrim<?>, JT extends SimpleJitType<T, JT>,
		N1 extends Next, N0 extends Ent<N1, T>> Emitter<N1> genWriteFromStack(Emitter<N0> em,
				Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitInputVar v, JT type,
				Ext ext, Scope scope) {
		throw new AssertionError();
	}

	@Override
	default <THIS extends JitCompiledPassage, N extends Next> Emitter<N> genWriteFromOpnd(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitInputVar v,
			Opnd<MpIntJitType> opnd, Ext ext, Scope scope) {
		throw new AssertionError();
	}

	@Override
	default <THIS extends JitCompiledPassage, N1 extends Next, N0 extends Ent<N1, TRef<int[]>>>
			Emitter<N1> genWriteFromArray(Emitter<N0> em, Local<TRef<THIS>> localThis,
					JitCodeGenerator<THIS> gen, JitInputVar v, MpIntJitType type, Ext ext,
					Scope scope) {
		throw new AssertionError();
	}

	@Override
	default <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TInt>> genReadToBool(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitInputVar v) {
		throw new AssertionError();
	}
}
