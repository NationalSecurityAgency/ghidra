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
package ghidra.pcode.emu.jit.gen;

import static ghidra.pcode.emu.jit.gen.GenConsts.*;
import static org.objectweb.asm.Opcodes.*;

import org.objectweb.asm.ClassVisitor;

import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.RegisterValue;

/**
 * A field request for pre-constructed contextreg value
 */
record FieldForContext(RegisterValue ctx) implements StaticFieldReq<TRef<RegisterValue>> {
	@Override
	public String name() {
		return "CTX_%s".formatted(ctx.getUnsignedValue().toString(16));
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Consider the context value 0x80000000. The code is equivalent to:
	 * 
	 * <pre>
	 * private static final {@link RegisterValue} CTX_80000000 = {@link JitCompiledPassage#createContext(Language, String) createContext}(LANGUAGE, "80000000");
	 * </pre>
	 */
	@Override
	public <N extends Next> Emitter<N> genClInitCode(Emitter<N> em, JitCodeGenerator<?> gen,
			ClassVisitor cv) {
		if (ctx == null) {
			return em;
		}
		Fld.decl(cv, ACC_PRIVATE | ACC_STATIC | ACC_FINAL, T_REGISTER_VALUE, name());
		return em
				.emit(Op::getstatic, gen.typeThis, "LANGUAGE", T_LANGUAGE)
				.emit(Op::ldc__a, ctx.getUnsignedValue().toString(16))
				.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE, "createContext",
					MDESC_JIT_COMPILED_PASSAGE__CREATE_CONTEXT, true)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::ret)
				.emit(Op::putstatic, gen.typeThis, name(), T_REGISTER_VALUE);
	}

	@Override
	public <N extends Next> Emitter<Ent<N, TRef<RegisterValue>>> genLoad(Emitter<N> em,
			JitCodeGenerator<?> gen) {
		return ctx == null
				? em.emit(Op::aconst_null, T_REGISTER_VALUE)
				: em.emit(Op::getstatic, gen.typeThis, name(), T_REGISTER_VALUE);
	}
}
