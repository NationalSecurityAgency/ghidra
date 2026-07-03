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
package ghidra.pcode.emu.jit.gen.op;

import java.util.function.Function;

import ghidra.pcode.emu.jit.analysis.JitType.SimpleJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Bot;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Types.BPrim;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.pcode.emu.jit.op.JitUnOp;

/**
 * An extension for float conversion operators
 * 
 * @param <T> the class of p-code op node in the use-def graph
 */
public interface FloatConvertUnOpGen<T extends JitUnOp> extends UnOpGen<T> {

	/**
	 * An implementation based on a given bytecode op
	 * 
	 * @param <THIS> the type of the generated passage
	 * @param <UT> the JVM type of the input operand
	 * @param <UJT> the p-code type of the input operand
	 * @param <OT> the JVM type of the output operand
	 * @param <OJT> the p-code type of the output operand
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @param op the p-code op
	 * @param ut the p-code type of the input operand
	 * @param ot the p-code type of the output operand
	 * @param opcode a method reference, e.g., to {@link Op#f2d(Emitter)} for the conversion
	 * @param scope a scope for generating temporary local storage
	 * @return the emitter typed with the incoming stack
	 */
	default <THIS extends JitCompiledPassage, UT extends BPrim<?>,
		UJT extends SimpleJitType<UT, UJT>, OT extends BPrim<?>,
		OJT extends SimpleJitType<OT, OJT>> Emitter<Bot> gen(Emitter<Bot> em,
				Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, T op, UJT ut, OJT ot,
				Function<? super Emitter<Ent<Bot, UT>>, Emitter<Ent<Bot, OT>>> opcode,
				Scope scope) {
		return em
				.emit(gen::genReadToStack, localThis, op.u(), ut, ext())
				.emit(opcode)
				.emit(gen::genWriteFromStack, localThis, op.out(), ot, ext(), scope);
	}
}
