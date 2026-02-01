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

import static ghidra.pcode.emu.jit.gen.GenConsts.MDESC_ASSERTION_ERROR__$INIT;
import static ghidra.pcode.emu.jit.gen.GenConsts.T_ASSERTION_ERROR;

import org.objectweb.asm.Opcodes;

import ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType;
import ghidra.pcode.emu.jit.analysis.JitType.SimpleJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.Opnd;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.OpndEm;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.op.JitPhiOp;
import ghidra.pcode.emu.jit.var.JitMissingVar;

/**
 * The generator for a missing (local) variable.
 * 
 * <p>
 * In principle, a {@link JitMissingVar} should never show up in the use-def graph, since they
 * should all be replaced by {@link JitPhiOp phi} outputs. We can be certain these should never show
 * up as an output, so we prohibit any attempt to generate code that writes to a missing variable.
 * However, we wait until run time to make that assertion about reads. In theory, it's possible the
 * generator will generate unreachable code that reads from a variable; however, that code is
 * unreachable. First, how does this happen? Second, what if it does?
 * 
 * <p>
 * To answer the first question, we note that the passage decoder should never decode any statically
 * unreachable instructions. However, the p-code emitted by those instructions may technically
 * contain unreachable ops.
 * 
 * <p>
 * To answer the second, we note that the ASM library has a built-in control-flow analyzer, and it
 * ought to detect the unreachable code. In my observation, it replaces that code with
 * {@link Opcodes#NOP nop} and/or {@link Opcodes#ATHROW athrow}. Still, in case it doesn't, or in
 * case something changes in a later version (or if/when we port this to the JDK's upcoming
 * classfile API), we emit our own bytecode to throw an {@link AssertionError}.
 */
public enum MissingVarGen implements VarGen<JitMissingVar> {
	/** Singleton */
	GEN;

	@Override
	public <THIS extends JitCompiledPassage, N extends Next> Emitter<N> genValInit(Emitter<N> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitMissingVar v) {
		return em;
	}

	private <N extends Next> Emitter<Dead> genThrow(Emitter<N> em, JitMissingVar v) {
		return em
				.emit(Op::new_, T_ASSERTION_ERROR)
				.emit(Op::dup)
				.emit(Op::ldc__a, "Tried to read " + v)
				.emit(Op::invokespecial, T_ASSERTION_ERROR, "<init>", MDESC_ASSERTION_ERROR__$INIT,
					false)
				.step(Inv::takeRefArg)
				.step(Inv::takeObjRef)
				.step(Inv::retVoid)
				.emit(Op::athrow);
	}

	@Override
	public <THIS extends JitCompiledPassage, T extends BPrim<?>, JT extends SimpleJitType<T, JT>,
		N extends Next> Emitter<Ent<N, T>> genReadToStack(Emitter<N> em,
				Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitMissingVar v, JT type,
				Ext ext) {
		genThrow(em, v);
		return null;
	}

	@Override
	public <THIS extends JitCompiledPassage, N extends Next> OpndEm<MpIntJitType, N> genReadToOpnd(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitMissingVar v,
			MpIntJitType type, Ext ext, Scope scope) {
		genThrow(em, v);
		return null;
	}

	@Override
	public <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TInt>>
			genReadLegToStack(Emitter<N> em, Local<TRef<THIS>> localThis,
					JitCodeGenerator<THIS> gen, JitMissingVar v, MpIntJitType type, int leg,
					Ext ext) {
		genThrow(em, v);
		return null;
	}

	@Override
	public <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TRef<int[]>>>
			genReadToArray(Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen,
					JitMissingVar v, MpIntJitType type, Ext ext, Scope scope, int slack) {
		genThrow(em, v);
		return null;
	}

	@Override
	public <THIS extends JitCompiledPassage, T extends BPrim<?>, JT extends SimpleJitType<T, JT>,
		N1 extends Next, N0 extends Ent<N1, T>> Emitter<N1> genWriteFromStack(Emitter<N0> em,
				Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitMissingVar v, JT type,
				Ext ext, Scope scope) {
		throw new AssertionError();
	}

	@Override
	public <THIS extends JitCompiledPassage, N extends Next> Emitter<N> genWriteFromOpnd(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitMissingVar v,
			Opnd<MpIntJitType> opnd, Ext ext, Scope scope) {
		throw new AssertionError();
	}

	@Override
	public <THIS extends JitCompiledPassage, N1 extends Next, N0 extends Ent<N1, TRef<int[]>>>
			Emitter<N1> genWriteFromArray(Emitter<N0> em, Local<TRef<THIS>> localThis,
					JitCodeGenerator<THIS> gen, JitMissingVar v, MpIntJitType type, Ext ext,
					Scope scope) {
		throw new AssertionError();
	}

	@Override
	public <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TInt>> genReadToBool(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen,
			JitMissingVar v) {
		throw new AssertionError();
	}

	@Override
	public ValGen<JitMissingVar> subpiece(int byteShift, int maxByteSize) {
		return this;
	}
}
