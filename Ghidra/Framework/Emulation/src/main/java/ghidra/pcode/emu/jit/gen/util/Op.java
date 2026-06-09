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
package ghidra.pcode.emu.jit.gen.util;

import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.objectweb.asm.*;

import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Lbl.LblEm;
import ghidra.pcode.emu.jit.gen.util.Methods.*;
import ghidra.pcode.emu.jit.gen.util.Types.*;

/**
 * This interface is a namespace that defines all (well most) JVM bytecode operations.
 * <p>
 * These also provide small examples of how to declare the type signatures for methods that generate
 * portions of bytecode. Inevitably, those methods will have expectations of what is on the stack,
 * and would like to express the overall effect on that stack in terms of the incoming stack.
 * Conventionally, generation methods should accept the emitter (typed with the incoming stack) as
 * its first parameter and return that emitter typed with the resulting stack. This allows those
 * methods to be invoked using, e.g., {@link Emitter#emit(Function)}, and also sets them up to use
 * the pattern:
 * 
 * <pre>
 * return em
 * 		.emit(Op::ldc__i, 1)
 * 		.emit(Op::iadd);
 * </pre>
 * <p>
 * With this pattern, the Java type checker will ensure that the expected effect on the stack is in
 * fact what the emitted code does. Once the pattern is understood, the type signature of each
 * opcode method is trivially derived from Chapter 6 of the JVM specification. We do, however, have
 * to treat each form separately. Method invocation opcodes require some additional support (see
 * {@link Inv}), because they consume arguments of arbitrary number and types.
 */
@SuppressWarnings({ "unchecked", "rawtypes" })
public interface Op {

	/**
	 * Emit an {@code aaload} instruction
	 * 
	 * @param <ET> the element type
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., arrayref
	 * @param <N0> ..., arrayref, index
	 * @param em the emitter
	 * @return the emitter with ..., value
	 */
	static <ET,
		N2 extends Next,
		N1 extends Ent<N2, TRef<ET[]>>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TRef<ET>>> aaload(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.AASTORE);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code aastore} instruction
	 * 
	 * @param <ET> the element type
	 * @param <N3> the tail of the stack (...)
	 * @param <N2> ..., arrayref
	 * @param <N1> ..., arrayref, index,
	 * @param <N0> ..., arrayref, index, value
	 * @param em the emitter
	 * @return the emitter with ...
	 */
	static <ET,
		N3 extends Next,
		N2 extends Ent<N3, TRef<ET[]>>,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, ? extends TRef<? extends ET>>>
			Emitter<N3> aastore(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.AASTORE);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code aconst_null} instruction
	 * 
	 * @param <T> the ascribed type of the {@code null}
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param type the ascribed type of the {@code null}
	 * @return the emitter with ..., {@code (T) null}
	 */
	static <T extends TRef<?>,
		N extends Next>
			Emitter<Ent<N, T>> aconst_null(Emitter<N> em, T type) {
		em.mv.visitInsn(Opcodes.ACONST_NULL);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code aload} instruction
	 * 
	 * @param <T> the type of the local
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param local the handle to the local
	 * @return the emitter with ..., value
	 */
	static <T extends TRef<?>,
		N extends Next>
			Emitter<Ent<N, T>> aload(Emitter<N> em, Local<T> local) {
		em.mv.visitVarInsn(Opcodes.ALOAD, local.index());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code anewarray} instruction
	 * 
	 * @param <ET> the element type
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., count
	 * @param em the emitter
	 * @param elemType the element type
	 * @return the emitter with ..., arrayref
	 */
	static <ET,
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N1, TRef<ET[]>>> anewarray(Emitter<N0> em, TRef<ET> elemType) {
		em.mv.visitTypeInsn(Opcodes.ANEWARRAY, elemType.internalName());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code areturn} instruction
	 * 
	 * @param <TL> the required return (ref) type
	 * @param <TR> the value (ref) type on the stack
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., objectref
	 * @param em the emitter
	 * @param retReq some proof of this method's required return type
	 * @return the dead emitter
	 */
	static <TL, TR,
		N1 extends Next,
		N0 extends Ent<N1, ? extends TRef<TR>>>
			Emitter<Dead> areturn(Emitter<N0> em, RetReq<? extends TRef<TL>> retReq) {
		em.mv.visitInsn(Opcodes.ARETURN);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code arraylength} instruction, when the array has primitive elements
	 * 
	 * @param <ET> the element type
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., arrayref
	 * @param em the emitter
	 * @param elemType the element type
	 * @return the emitter with ..., length
	 */
	static <AT, ET extends SPrim<AT>,
		N1 extends Next,
		N0 extends Ent<N1, TRef<AT>>>
			Emitter<Ent<N1, TInt>> arraylength__prim(Emitter<N0> em, ET elemType) {
		em.mv.visitInsn(Opcodes.ARRAYLENGTH);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code arraylength} instruction, when the array has reference elements
	 * 
	 * @param <ET> the element type
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., arrayref
	 * @param em the emitter
	 * @return the emitter with ..., length
	 */
	static <ET,
		N1 extends Next,
		N0 extends Ent<N1, TRef<ET[]>>>
			Emitter<Ent<N1, TInt>> arraylength__ref(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.ARRAYLENGTH);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code astore} instruction
	 * 
	 * @param <TL> the local variable (ref) type
	 * @param <TR> the value (ref) type on the stack
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., objectref
	 * @param em the emitter
	 * @param local the target local variable
	 * @return the emitter with ...
	 */
	static <TL, TR,
		N1 extends Next,
		N0 extends Ent<N1, ? extends TRef<TR>>>
			Emitter<N1> astore(Emitter<N0> em, Local<? extends TRef<TL>> local) {
		em.mv.visitVarInsn(Opcodes.ASTORE, local.index());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code athrow} instruction
	 * 
	 * @param <T1> the value (Throwable ref) type on the stack
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., objectref
	 * @param em the emitter
	 * @return the dead emitter
	 */
	static <T1 extends TRef<? extends Throwable>,
		N1 extends Next,
		N0 extends Ent<N1, T1>>
			Emitter<Dead> athrow(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.ATHROW);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code baload} instruction for a boolean array
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., arrayref
	 * @param <N0> ..., arrayref, index
	 * @param em the emitter
	 * @return the emitter with ..., value
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TRef<boolean[]>>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> baload__boolean(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.BALOAD);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code baload} instruction for a byte array
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., arrayref
	 * @param <N0> ..., arrayref, index
	 * @param em the emitter
	 * @return the emitter with ..., value
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TRef<byte[]>>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> baload(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.BALOAD);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code bastore} instruction for a boolean array
	 * 
	 * @param <N3> the tail of the stack (...)
	 * @param <N2> ..., arrayref
	 * @param <N1> ..., arrayref, index
	 * @param <N0> ..., arrayref, index, value
	 * @param em the emitter
	 * @return the emitter with ...
	 */
	static <
		N3 extends Next,
		N2 extends Ent<N3, TRef<boolean[]>>,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<N3> bastore__boolean(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.BASTORE);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code bastore} instruction for a byte array
	 * 
	 * @param <N3> the tail of the stack (...)
	 * @param <N2> ..., arrayref
	 * @param <N1> ..., arrayref, index
	 * @param <N0> ..., arrayref, index, value
	 * @param em the emitter
	 * @return the emitter with ...
	 */
	static <
		N3 extends Next,
		N2 extends Ent<N3, TRef<byte[]>>,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<N3> bastore(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.BASTORE);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code caload} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., arrayref
	 * @param <N0> ..., arrayref, index
	 * @param em the emitter
	 * @return the emitter with ..., value
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TRef<char[]>>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> caload(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.CALOAD);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code castore} instruction
	 * 
	 * @param <N3> the tail of the stack (...)
	 * @param <N2> ..., arrayref
	 * @param <N1> ..., arrayref, index
	 * @param <N0> ..., arrayref, index, value
	 * @param em the emitter
	 * @return the emitter with ...
	 */
	static <
		N3 extends Next,
		N2 extends Ent<N3, TRef<char[]>>,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<N3> castore(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.CASTORE);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code checkcast} instruction
	 * 
	 * @param <ST> the inferred type of the value on the stack, i.e., the less-specific type
	 * @param <CT> the desired type, i.e., the more-specific type
	 * @param <T1> the reference type for the inferred type
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., objectref
	 * @param em the emitter
	 * @param type the reference type for the desired type
	 * @return the emitter with ..., objectref
	 */
	static <ST, CT extends ST, T1 extends TRef<ST>,
		N1 extends Next,
		N0 extends Ent<N1, T1>>
			Emitter<Ent<N1, TRef<CT>>> checkcast(Emitter<N0> em, TRef<CT> type) {
		em.mv.visitTypeInsn(Opcodes.CHECKCAST, type.internalName());
		return (Emitter) em;
	}

	/**
	 * Emit a {@code d2f} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TDouble>>
			Emitter<Ent<N1, TFloat>> d2f(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.D2F);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code d2i} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TDouble>>
			Emitter<Ent<N1, TInt>> d2i(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.D2I);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code d2l} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TDouble>>
			Emitter<Ent<N1, TLong>> d2l(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.D2L);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dadd} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TDouble>,
		N0 extends Ent<N1, TDouble>>
			Emitter<Ent<N2, TDouble>> dadd(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DADD);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code daload} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., arrayref
	 * @param <N0> ..., arrayref, index
	 * @param em the emitter
	 * @return the emitter with ..., value
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TRef<double[]>>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TDouble>> daload(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DALOAD);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dastore} instruction
	 * 
	 * @param <N3> the tail of the stack (...)
	 * @param <N2> ..., arrayref
	 * @param <N1> ..., arrayref, index
	 * @param <N0> ..., arrayref, index, value
	 * @param em the emitter
	 * @return the emitter with ...
	 */
	static <
		N3 extends Next,
		N2 extends Ent<N3, TRef<double[]>>,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TDouble>>
			Emitter<N3> dastore(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DASTORE);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dcmpg} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TDouble>,
		N0 extends Ent<N1, TDouble>>
			Emitter<Ent<N2, TInt>> dcmpg(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DCMPG);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dcmpl} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TDouble>,
		N0 extends Ent<N1, TDouble>>
			Emitter<Ent<N2, TInt>> dcmpl(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DCMPL);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code ddiv} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TDouble>,
		N0 extends Ent<N1, TDouble>>
			Emitter<Ent<N2, TDouble>> ddiv(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DDIV);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dload} instruction
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param local the handle to the local
	 * @return the emitter with ..., value
	 */
	static <N extends Next>
			Emitter<Ent<N, TDouble>> dload(Emitter<N> em, Local<TDouble> local) {
		em.mv.visitVarInsn(Opcodes.DLOAD, local.index());
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dmul} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TDouble>,
		N0 extends Ent<N1, TDouble>>
			Emitter<Ent<N2, TDouble>> dmul(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DMUL);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dneg} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TDouble>>
			Emitter<Ent<N1, TDouble>> dneg(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DNEG);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code drem} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TDouble>,
		N0 extends Ent<N1, TDouble>>
			Emitter<Ent<N2, TDouble>> drem(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DREM);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dreturn} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param retReq some proof of this method's required return type
	 * @return the dead emitter
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TDouble>>
			Emitter<Dead> dreturn(Emitter<N0> em, RetReq<TDouble> retReq) {
		em.mv.visitInsn(Opcodes.DRETURN);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dstore} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param local the target local variable
	 * @return the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TDouble>>
			Emitter<N1> dstore(Emitter<N0> em, Local<TDouble> local) {
		em.mv.visitVarInsn(Opcodes.DSTORE, local.index());
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dsub} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TDouble>,
		N0 extends Ent<N1, TDouble>>
			Emitter<Ent<N2, TDouble>> dsub(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DSUB);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dup} instruction
	 * 
	 * @param <V1> the type of the value on the stack
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., value, value
	 */
	static <V1 extends TCat1,
		N1 extends Next,
		N0 extends Ent<N1, V1>>
			Emitter<Ent<N0, V1>> dup(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DUP);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dup_x1} instruction
	 * 
	 * @param <V2> the type of value2 on the stack
	 * @param <V1> the type of value1 on the stack
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value2
	 * @param <N0> ..., value2, value1
	 * @param em the emitter
	 * @return the emitter with ..., value1, value2, value1
	 */
	static <V2 extends TCat1, V1 extends TCat1,
		N2 extends Next,
		N1 extends Ent<N2, V2>,
		N0 extends Ent<N1, V1>>
			Emitter<Ent<Ent<Ent<N2, V1>, V2>, V1>> dup_x1(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DUP_X1);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dup_x2} instruction, inserting 3 values down (Form 1)
	 * 
	 * @param <V3> the type of value3 on the stack
	 * @param <V2> the type of value2 on the stack
	 * @param <V1> the type of value1 on the stack
	 * @param <N3> the tail of the stack (...)
	 * @param <N2> ..., value3
	 * @param <N1> ..., value3, value2
	 * @param <N0> ..., value3, value2, value1
	 * @param em the emitter
	 * @return the emitter with ..., value1, value3, value2, value1
	 */
	static <V3 extends TCat1, V2 extends TCat1, V1 extends TCat1,
		N3 extends Next,
		N2 extends Ent<N3, V3>,
		N1 extends Ent<N2, V2>,
		N0 extends Ent<N1, V1>>
			Emitter<Ent<Ent<Ent<Ent<N3, V1>, V3>, V2>, V1>> dup_x2__111(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DUP_X2);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dup_x2} instruction, inserting 2 values down (Form 2)
	 * 
	 * @param <V2> the type of value2 on the stack
	 * @param <V1> the type of value1 on the stack
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value2
	 * @param <N0> ..., value2, value1
	 * @param em the emitter
	 * @return the emitter with ..., value1, value2, value1
	 */
	static <V2 extends TCat2, V1 extends TCat1,
		N2 extends Next,
		N1 extends Ent<N2, V2>,
		N0 extends Ent<N1, V1>>
			Emitter<Ent<Ent<Ent<N2, V1>, V2>, V1>> dup_x2__21(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DUP_X2);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dup2} instruction, duplicating two operands (Form 1)
	 * 
	 * @param <V2> the type of value2 on the stack
	 * @param <V1> the type of vlaue1 on the stack
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value2
	 * @param <N0> ..., value2, value1
	 * @param em the emitter
	 * @return the emitter with ..., value2, value1, value2, value1
	 */
	static <V2 extends TCat1, V1 extends TCat1,
		N2 extends Next,
		N1 extends Ent<N2, V2>,
		N0 extends Ent<N1, V1>>
			Emitter<Ent<Ent<N0, V2>, V1>> dup2__11(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DUP2);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dup2} instruction, duplicating one operand (Form 2)
	 * 
	 * @param <V1> the type of the value on the stack
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., value, value
	 */
	static <V1 extends TCat2,
		N1 extends Next,
		N0 extends Ent<N1, V1>>
			Emitter<Ent<N0, V1>> dup2__2(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DUP2);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dup2_x1} instruction, duplicating two operands, three values down (Form 1)
	 * 
	 * @param <V3> the type of value3 on the stack
	 * @param <V2> the type of value2 on the stack
	 * @param <V1> the type of value1 on the stack
	 * @param <N3> the tail of the stack (...)
	 * @param <N2> ..., value3
	 * @param <N1> ..., value3, value2
	 * @param <N0> ..., value3, value2, value1
	 * @param em the emitter
	 * @return the emitter with ..., value2, value1, value3, value2, value1
	 */
	static <V3 extends TCat1, V2 extends TCat1, V1 extends TCat1,
		N3 extends Next,
		N2 extends Ent<N3, V3>,
		N1 extends Ent<N2, V2>,
		N0 extends Ent<N1, V1>>
			Emitter<Ent<Ent<Ent<Ent<Ent<N3, V2>, V1>, V3>, V2>, V1>> dup2_x1__111(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DUP2_X1);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dup2_x1} instruction, duplicating one operand, two values down (Form 2)
	 * 
	 * @param <V2> the type of value2 on the stack
	 * @param <V1> the type of value1 on the stack
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value2
	 * @param <N0> ..., value2, value1
	 * @param em the emitter
	 * @return the emitter with ..., value1, value2, value1
	 */
	static <V2 extends TCat1, V1 extends TCat2,
		N2 extends Next,
		N1 extends Ent<N2, V2>,
		N0 extends Ent<N1, V1>>
			Emitter<Ent<Ent<Ent<N2, V1>, V2>, V1>> dup2_x1__12(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DUP2_X1);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dup2_x2} instruction, duplicating two operands, four values down (Form 1)
	 * 
	 * @param <V4> the type of value4 on the stack
	 * @param <V3> the type of value3 on the stack
	 * @param <V2> the type of value2 on the stack
	 * @param <V1> the type of value1 on the stack
	 * @param <N4> the tail of the stack (...)
	 * @param <N3> ..., value4
	 * @param <N2> ..., value4, value3
	 * @param <N1> ..., value4, value3, value2
	 * @param <N0> ..., value4, value3, value2, value1
	 * @param em the emitter
	 * @return the emitter with ..., value2, value1, value4, value3, value2, value1
	 */
	static <V4 extends TCat1, V3 extends TCat1, V2 extends TCat1, V1 extends TCat1,
		N4 extends Next,
		N3 extends Ent<N4, V4>,
		N2 extends Ent<N3, V3>,
		N1 extends Ent<N2, V2>,
		N0 extends Ent<N1, V1>>
			Emitter<Ent<Ent<Ent<Ent<Ent<Ent<N4, V2>, V1>, V4>, V3>, V2>, V1>>
			dup2_x2_1111(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DUP2_X2);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dup2_x2} instruction, duplicating one operand, three values down (Form 2)
	 * 
	 * @param <V3> the type of value3 on the stack
	 * @param <V2> the type of value2 on the stack
	 * @param <V1> the type of value1 on the stack
	 * @param <N3> the tail of the stack (...)
	 * @param <N2> ..., value3
	 * @param <N1> ..., value3, value2
	 * @param <N0> ..., value3, value2, value1
	 * @param em the emitter
	 * @return the emitter with ..., value1, value3, value2, value1
	 */
	static <V3 extends TCat1, V2 extends TCat1, V1 extends TCat2,
		N3 extends Next,
		N2 extends Ent<N3, V3>,
		N1 extends Ent<N2, V2>,
		N0 extends Ent<N1, V1>>
			Emitter<Ent<Ent<Ent<Ent<N3, V1>, V3>, V2>, V1>> dup2_x2_112(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DUP2_X2);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dup2_x2} instruction, duplicating two operands, three values down (Form 3)
	 * 
	 * @param <V3> the type of value3 on the stack
	 * @param <V2> the type of value2 on the stack
	 * @param <V1> the type of value1 on the stack
	 * @param <N3> the tail of the stack (...)
	 * @param <N2> ..., value3
	 * @param <N1> ..., value3, value2
	 * @param <N0> ..., value3, value2, value1
	 * @param em the emitter
	 * @return the emitter with ..., value2, value1, value3, value2, value1
	 */
	static <V3 extends TCat2, V2 extends TCat1, V1 extends TCat1,
		N3 extends Next,
		N2 extends Ent<N3, V3>,
		N1 extends Ent<N2, V2>,
		N0 extends Ent<N1, V1>>
			Emitter<Ent<Ent<Ent<Ent<Ent<N3, V2>, V1>, V3>, V2>, V1>> dup2_x2_211(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DUP2_X2);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code dup2_x2} instruction, duplicating one operand, two values down (Form 4)
	 * 
	 * @param <V2> the type of value2 on the stack
	 * @param <V1> the type of value1 on the stack
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value2
	 * @param <N0> ..., value2, value1
	 * @param em the emitter
	 * @return the emitter with ..., value1, value2, value1
	 */
	static <V2 extends TCat2, V1 extends TCat2,
		N2 extends Next,
		N1 extends Ent<N2, V2>,
		N0 extends Ent<N1, V1>>
			Emitter<Ent<Ent<Ent<N2, V1>, V2>, V1>> dup2_x2_22(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.DUP2_X2);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code f2d} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TFloat>>
			Emitter<Ent<N1, TDouble>> f2d(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.F2D);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code f2i} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TFloat>>
			Emitter<Ent<N1, TInt>> f2i(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.F2I);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code f2l} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TFloat>>
			Emitter<Ent<N1, TLong>> f2l(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.F2L);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code fadd} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TFloat>,
		N0 extends Ent<N1, TFloat>>
			Emitter<Ent<N2, TFloat>> fadd(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.FADD);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code faload} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., arrayref
	 * @param <N0> ..., arrayref, index
	 * @param em the emitter
	 * @return the emitter with ..., value
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TRef<float[]>>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TFloat>> faload(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.FALOAD);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code fastore} instruction
	 * 
	 * @param <N3> the tail of the stack (...)
	 * @param <N2> ..., arrayref
	 * @param <N1> ..., arrayref, index
	 * @param <N0> ..., arrayref, index, value
	 * @param em the emitter
	 * @return the emitter with ...
	 */
	static <
		N3 extends Next,
		N2 extends Ent<N3, TRef<float[]>>,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TFloat>>
			Emitter<N3> fastore(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.FASTORE);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code fcmpg} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TFloat>,
		N0 extends Ent<N1, TFloat>>
			Emitter<Ent<N2, TInt>> fcmpg(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.FCMPG);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code fcmpl} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TFloat>,
		N0 extends Ent<N1, TFloat>>
			Emitter<Ent<N2, TInt>> fcmpl(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.FCMPL);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code fdiv} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TFloat>,
		N0 extends Ent<N1, TFloat>>
			Emitter<Ent<N2, TFloat>> fdiv(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.FDIV);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code fload} instruction
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param local the handle to the local
	 * @return the emitter with ..., value
	 */
	static <N extends Next>
			Emitter<Ent<N, TFloat>> fload(Emitter<N> em, Local<TFloat> local) {
		em.mv.visitVarInsn(Opcodes.FLOAD, local.index());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code fmul} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TFloat>,
		N0 extends Ent<N1, TFloat>>
			Emitter<Ent<N2, TFloat>> fmul(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.FMUL);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code fneg} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TFloat>>
			Emitter<Ent<N1, TFloat>> fneg(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.FNEG);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code frem} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TFloat>,
		N0 extends Ent<N1, TFloat>>
			Emitter<Ent<N2, TFloat>> frem(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.FREM);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code freturn} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param retReq some proof of this method's required return type
	 * @return the dead emitter
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TFloat>>
			Emitter<Dead> freturn(Emitter<N0> em, RetReq<TFloat> retReq) {
		em.mv.visitInsn(Opcodes.FRETURN);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code fstore} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param local the target local variable
	 * @return the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TFloat>>
			Emitter<N1> fstore(Emitter<N0> em, Local<TFloat> local) {
		em.mv.visitVarInsn(Opcodes.FSTORE, local.index());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code fsub} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TFloat>,
		N0 extends Ent<N1, TFloat>>
			Emitter<Ent<N2, TFloat>> fsub(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.FSUB);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code getfield} instruction
	 * <p>
	 * LATER: Some sort of field handle?
	 * 
	 * @param <OT> the owner type
	 * @param <T1> the type of the object on the stack owning the field
	 * @param <FT> the type of the field
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., objectref
	 * @param em the emitter
	 * @param owner the owner type
	 * @param name the name of the field
	 * @param type the type of the field
	 * @return the emitter with ..., value
	 */
	static <OT,
		T1 extends TRef<? extends OT>,
		FT extends BNonVoid,
		N1 extends Next,
		N0 extends Ent<N1, T1>>
			Emitter<Ent<N1, FT>> getfield(Emitter<N0> em, TRef<OT> owner, String name, FT type) {
		em.mv.visitFieldInsn(Opcodes.GETFIELD, owner.type().getInternalName(), name,
			type.type().getDescriptor());
		return (Emitter) em;
	}

	/**
	 * Emit a {@code getstatic} instruction
	 * <p>
	 * LATER: Some sort of field handle?
	 * 
	 * @param <FT> the type of the field
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param owner the owner type
	 * @param name the name of the field
	 * @param type the type of the field
	 * @return the emitter with ..., value
	 */
	static <FT extends BNonVoid,
		N extends Next>
			Emitter<Ent<N, FT>> getstatic(Emitter<N> em, TRef<?> owner, String name, FT type) {
		em.mv.visitFieldInsn(Opcodes.GETSTATIC, owner.type().getInternalName(), name,
			type.type().getDescriptor());
		return (Emitter) em;
	}

	/**
	 * Emit a {@code goto} instruction to a new target label
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @return the new target label and the dead emitter
	 */
	static <N extends Next>
			LblEm<N, Dead> goto_(Emitter<N> em) {
		Lbl<N> target = Lbl.create();
		em.mv.visitJumpInsn(Opcodes.GOTO, target.label());
		return new LblEm<>(target, (Emitter) em);
	}

	/**
	 * Emit a {@code goto} instruction to a given target label
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param target the target label
	 * @return the dead emitter
	 */
	static <N extends Next>
			Emitter<Dead> goto_(Emitter<N> em, Lbl<N> target) {
		em.mv.visitJumpInsn(Opcodes.GOTO, target.label());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code i2b} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N1, TInt>> i2b(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.I2B);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code i2c} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N1, TInt>> i2c(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.I2C);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code i2d} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N1, TDouble>> i2d(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.I2D);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code i2f} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N1, TFloat>> i2f(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.I2F);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code i2l} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N1, TLong>> i2l(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.I2L);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code i2s} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N1, TInt>> i2s(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.I2S);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code iadd} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> iadd(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.IADD);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code iaload} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., arrayref
	 * @param <N0> ..., arrayref, index
	 * @param em the emitter
	 * @return the emitter with ..., value
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TRef<int[]>>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> iaload(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.IALOAD);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code iand} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> iand(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.IAND);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code iastore} instruction
	 * 
	 * @param <N3> the tail of the stack (...)
	 * @param <N2> ..., arrayref
	 * @param <N1> ..., arrayref, index
	 * @param <N0> ..., arrayref, index, value
	 * @param em the emitter
	 * @return the emitter with ...
	 */
	static <
		N3 extends Next,
		N2 extends Ent<N3, TRef<int[]>>,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<N3> iastore(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.IASTORE);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code idiv} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> idiv(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.IDIV);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code if_acmpeq} instruction to a new target label
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the new target label and the emitter with ...
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TRef<?>>,
		N0 extends Ent<N1, TRef<?>>>
			LblEm<N2, N2> if_acmpeq(Emitter<N0> em) {
		Lbl<N2> target = Lbl.create();
		em.mv.visitJumpInsn(Opcodes.IF_ACMPEQ, target.label());
		return new LblEm<>(target, (Emitter) em);
	}

	/**
	 * Emit an {@code if_acmpeq} instruction to a given target label
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @param target the target label
	 * @return the emitter with ...
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TRef<?>>,
		N0 extends Ent<N1, TRef<?>>>
			Emitter<N2> if_acmpeq(Emitter<N0> em, Lbl<N2> target) {
		em.mv.visitJumpInsn(Opcodes.IF_ACMPEQ, target.label());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code if_acmpne} instruction to a new target label
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the new target label and the emitter with ...
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TRef<?>>,
		N0 extends Ent<N1, TRef<?>>>
			LblEm<N2, N2> if_acmpne(Emitter<N0> em) {
		Lbl<N2> target = Lbl.create();
		em.mv.visitJumpInsn(Opcodes.IF_ACMPNE, target.label());
		return new LblEm<>(target, (Emitter) em);
	}

	/**
	 * Emit an {@code if_acmpne} instruction to a given target label
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @param target the target label
	 * @return the emitter with ...
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TRef<?>>,
		N0 extends Ent<N1, TRef<?>>>
			Emitter<N2> if_acmpne(Emitter<N0> em, Lbl<N2> target) {
		em.mv.visitJumpInsn(Opcodes.IF_ACMPNE, target.label());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code if_icmpeq} instruction to a new target label
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the new target label and the emitter with ...
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			LblEm<N2, N2> if_icmpeq(Emitter<N0> em) {
		Lbl<N2> target = Lbl.create();
		em.mv.visitJumpInsn(Opcodes.IF_ICMPEQ, target.label());
		return new LblEm<>(target, (Emitter) em);
	}

	/**
	 * Emit an {@code if_icmpeq} instruction to a given target label
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @param target the target label
	 * @return the emitter with ...
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<N2> if_icmpeq(Emitter<N0> em, Lbl<N2> target) {
		em.mv.visitJumpInsn(Opcodes.IF_ICMPEQ, target.label());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code if_icmpge} instruction to a new target label
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the new target label and the emitter with ...
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			LblEm<N2, N2> if_icmpge(Emitter<N0> em) {
		Lbl<N2> target = Lbl.create();
		em.mv.visitJumpInsn(Opcodes.IF_ICMPGE, target.label());
		return new LblEm<>(target, (Emitter) em);
	}

	/**
	 * Emit an {@code if_icmpge} instruction to a given target label
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @param target the target label
	 * @return the emitter with ...
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<N2> if_icmpge(Emitter<N0> em, Lbl<N2> target) {
		em.mv.visitJumpInsn(Opcodes.IF_ICMPGE, target.label());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code if_icmpgt} instruction to a new target label
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the new target label and the emitter with ...
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			LblEm<N2, N2> if_icmpgt(Emitter<N0> em) {
		Lbl<N2> target = Lbl.create();
		em.mv.visitJumpInsn(Opcodes.IF_ICMPGT, target.label());
		return new LblEm<>(target, (Emitter) em);
	}

	/**
	 * Emit an {@code if_icmpgt} instruction to a given target label
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @param target the target label
	 * @return the emitter with ...
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<N2> if_icmpgt(Emitter<N0> em, Lbl<N2> target) {
		em.mv.visitJumpInsn(Opcodes.IF_ICMPGT, target.label());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code if_icmple} instruction to a new target label
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the new target label and the emitter with ...
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			LblEm<N2, N2> if_icmple(Emitter<N0> em) {
		Lbl<N2> target = Lbl.create();
		em.mv.visitJumpInsn(Opcodes.IF_ICMPLE, target.label());
		return new LblEm<>(target, (Emitter) em);
	}

	/**
	 * Emit an {@code if_icmple} instruction to a given target label
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @param target the target label
	 * @return the emitter with ...
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<N2> if_icmple(Emitter<N0> em, Lbl<N2> target) {
		em.mv.visitJumpInsn(Opcodes.IF_ICMPLE, target.label());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code if_icmplt} instruction to a new target label
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the new target label and the emitter with ...
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			LblEm<N2, N2> if_icmplt(Emitter<N0> em) {
		Lbl<N2> target = Lbl.create();
		em.mv.visitJumpInsn(Opcodes.IF_ICMPLT, target.label());
		return new LblEm<>(target, (Emitter) em);
	}

	/**
	 * Emit an {@code if_icmplt} instruction to a given target label
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @param target the target label
	 * @return the emitter with ...
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<N2> if_icmplt(Emitter<N0> em, Lbl<N2> target) {
		em.mv.visitJumpInsn(Opcodes.IF_ICMPLT, target.label());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code if_icmpne} instruction to a new target label
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the new target label and the emitter with ...
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			LblEm<N2, N2> if_icmpne(Emitter<N0> em) {
		Lbl<N2> target = Lbl.create();
		em.mv.visitJumpInsn(Opcodes.IF_ICMPNE, target.label());
		return new LblEm<>(target, (Emitter) em);
	}

	/**
	 * Emit an {@code if_icmpne} instruction to a given target label
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @param target the target label
	 * @return the emitter with ...
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<N2> if_icmpne(Emitter<N0> em, Lbl<N2> target) {
		em.mv.visitJumpInsn(Opcodes.IF_ICMPNE, target.label());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ifeq} instruction to a new target label
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the new target label and the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			LblEm<N1, N1> ifeq(Emitter<N0> em) {
		Lbl<N1> target = Lbl.create();
		em.mv.visitJumpInsn(Opcodes.IFEQ, target.label());
		return new LblEm<>(target, (Emitter) em);
	}

	/**
	 * Emit an {@code ifeq} instruction to a given target label
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param target the target label
	 * @return the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			Emitter<N1> ifeq(Emitter<N0> em, Lbl<N1> target) {
		em.mv.visitJumpInsn(Opcodes.IFEQ, target.label());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ifge} instruction to a new target label
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the new target label and the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			LblEm<N1, N1> ifge(Emitter<N0> em) {
		Lbl<N1> target = Lbl.create();
		em.mv.visitJumpInsn(Opcodes.IFGE, target.label());
		return new LblEm<>(target, (Emitter) em);
	}

	/**
	 * Emit an {@code ifge} instruction to a given target label
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param target the target label
	 * @return the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			Emitter<N1> ifge(Emitter<N0> em, Lbl<N1> target) {
		em.mv.visitJumpInsn(Opcodes.IFGE, target.label());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ifgt} instruction to a new target label
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the new target label and the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			LblEm<N1, N1> ifgt(Emitter<N0> em) {
		Lbl<N1> target = Lbl.create();
		em.mv.visitJumpInsn(Opcodes.IFGT, target.label());
		return new LblEm<>(target, (Emitter) em);
	}

	/**
	 * Emit an {@code ifgt} instruction to a given target label
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param target the target label
	 * @return the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			Emitter<N1> ifgt(Emitter<N0> em, Lbl<N1> target) {
		em.mv.visitJumpInsn(Opcodes.IFGT, target.label());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ifle} instruction to a new target label
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the new target label and the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			LblEm<N1, N1> ifle(Emitter<N0> em) {
		Lbl<N1> target = Lbl.create();
		em.mv.visitJumpInsn(Opcodes.IFLE, target.label());
		return new LblEm<>(target, (Emitter) em);
	}

	/**
	 * Emit an {@code ifle} instruction to a given target label
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param target the target label
	 * @return the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			Emitter<N1> ifle(Emitter<N0> em, Lbl<N1> target) {
		em.mv.visitJumpInsn(Opcodes.IFLE, target.label());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code iflt} instruction to a new target label
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the new target label and the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			LblEm<N1, N1> iflt(Emitter<N0> em) {
		Lbl<N1> target = Lbl.create();
		em.mv.visitJumpInsn(Opcodes.IFLT, target.label());
		return new LblEm<>(target, (Emitter) em);
	}

	/**
	 * Emit an {@code iflt} instruction to a given target label
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param target the target label
	 * @return the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			Emitter<N1> iflt(Emitter<N0> em, Lbl<N1> target) {
		em.mv.visitJumpInsn(Opcodes.IFLT, target.label());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ifne} instruction to a new target label
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the new target label and the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			LblEm<N1, N1> ifne(Emitter<N0> em) {
		Lbl<N1> target = Lbl.create();
		em.mv.visitJumpInsn(Opcodes.IFNE, target.label());
		return new LblEm<>(target, (Emitter) em);
	}

	/**
	 * Emit an {@code ifne} instruction to a given target label
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param target the target label
	 * @return the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			Emitter<N1> ifne(Emitter<N0> em, Lbl<N1> target) {
		em.mv.visitJumpInsn(Opcodes.IFNE, target.label());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ifnonnull} instruction to a new target label
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the new target label and the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TRef<?>>>
			LblEm<N1, N1> ifnonnull(Emitter<N0> em) {
		Lbl<N1> target = Lbl.create();
		em.mv.visitJumpInsn(Opcodes.IFNONNULL, target.label());
		return new LblEm<>(target, (Emitter) em);
	}

	/**
	 * Emit an {@code ifnonnull} instruction to a given target label
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param target the target label
	 * @return the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TRef<?>>>
			Emitter<N1> ifnonnull(Emitter<N0> em, Lbl<N1> target) {
		em.mv.visitJumpInsn(Opcodes.IFNONNULL, target.label());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ifnull} instruction to a new target label
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the new target label and the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TRef<?>>>
			LblEm<N1, N1> ifnull(Emitter<N0> em) {
		Lbl<N1> target = Lbl.create();
		em.mv.visitJumpInsn(Opcodes.IFNULL, target.label());
		return new LblEm<>(target, (Emitter) em);
	}

	/**
	 * Emit an {@code ifnull} instruction to a given target label
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param target the target label
	 * @return the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TRef<?>>>
			Emitter<N1> ifnull(Emitter<N0> em, Lbl<N1> target) {
		em.mv.visitJumpInsn(Opcodes.IFNULL, target.label());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code iinc} instruction
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param local the target local to increment
	 * @param increment the constant value to increment by
	 * @return the emitter with ...
	 */
	static <N extends Next>
			Emitter<N> iinc(Emitter<N> em, Local<TInt> local, int increment) {
		em.mv.visitIincInsn(local.index(), increment);
		return em;
	}

	/**
	 * Emit an {@code iload} instruction
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param local the handle to the local
	 * @return the emitter with ..., value
	 */
	static <N extends Next>
			Emitter<Ent<N, TInt>> iload(Emitter<N> em, Local<TInt> local) {
		em.mv.visitVarInsn(Opcodes.ILOAD, local.index());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code imul} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> imul(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.IMUL);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ineg} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N1, TInt>> ineg(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.INEG);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code instanceof} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., objectref
	 * @param em the emitter
	 * @param type the given type (T)
	 * @return the emitter with ..., result
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TRef<?>>>
			Emitter<Ent<N1, TInt>> instanceof_(Emitter<N0> em, TRef<?> type) {
		em.mv.visitTypeInsn(Opcodes.INSTANCEOF, type.internalName());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code invokedynamic} instruction
	 * <p>
	 * <b>WARNING:</b> This is probably not implemented correctly. The JVM spec does not provide an
	 * example, but the best we can tell, after all the call site resolution machinery, the net
	 * arguments actually consumed from the stack is determined by the given method descriptor. We
	 * also just let the ASM types {@link Type}, {@link Handle}, and {@link ConstantDynamic} leak
	 * from an API perspective.
	 * 
	 * @param <SN> the JVM stack at the call site. Some may be popped as arguments
	 * @param <MN> the parameters expected by the method descriptor
	 * @param <MR> the return type from the method descriptor
	 * @param em the emitter
	 * @param name the name of the method
	 * @param desc the method descriptor
	 * @param bootstrapMethodHandle as in
	 *            {@link MethodVisitor#visitInvokeDynamicInsn(String, String, Handle, Object...)}
	 * @param bootstrapMethodArguments as in
	 *            {@link MethodVisitor#visitInvokeDynamicInsn(String, String, Handle, Object...)}
	 * @return an object to complete type checking of the arguments and, if applicable, the result
	 */
	static <
		SN extends Next,
		MN extends Next,
		MR extends BType>
			Inv<MR, SN, MN> invokedynamic__unsupported(Emitter<SN> em, String name,
					MthDesc<MR, MN> desc, Handle bootstrapMethodHandle,
					Object... bootstrapMethodArguments) {
		em.mv.visitInvokeDynamicInsn(name, desc.desc(), bootstrapMethodHandle,
			bootstrapMethodArguments);
		return new Inv<>(em);
	}

	/**
	 * Emit an {@code invokeinterface} instruction
	 * 
	 * @param <OT> the owner (interface) type
	 * @param <SN> the JVM stack at the call site. Some may be popped as arguments
	 * @param <MN> the parameters expected by the method descriptor
	 * @param <MR> the return type from the method descriptor
	 * @param em the emitter
	 * @param ownerType the owner (interface) type
	 * @param name the name of the method
	 * @param desc the method descriptor
	 * @return an object to complete type checking of the arguments and, if applicable, the result
	 */
	static <OT,
		SN extends Next,
		MN extends Next,
		MR extends BType>
			ObjInv<MR, OT, SN, MN>
			invokeinterface(Emitter<SN> em, TRef<OT> ownerType, String name, MthDesc<MR, MN> desc) {
		em.mv.visitMethodInsn(Opcodes.INVOKEINTERFACE, ownerType.internalName(),
			name,
			desc.desc(), true);
		return new ObjInv<>(em);
	}

	/**
	 * Emit an {@code invokespecial} instruction
	 * 
	 * @param <OT> the owner (super) type
	 * @param <SN> the JVM stack at the call site. Some may be popped as arguments
	 * @param <MN> the parameters expected by the method descriptor
	 * @param <MR> the return type from the method descriptor
	 * @param em the emitter
	 * @param ownerType the owner (super) type
	 * @param name the name of the method
	 * @param desc the method descriptor
	 * @param isInterface true to indicate the owner type is an interface
	 * @return an object to complete type checking of the arguments and, if applicable, the result
	 */
	static <OT,
		SN extends Next,
		MN extends Next,
		MR extends BType>
			ObjInv<MR, OT, SN, MN> invokespecial(Emitter<SN> em, TRef<OT> ownerType, String name,
					MthDesc<MR, MN> desc, boolean isInterface) {
		em.mv.visitMethodInsn(Opcodes.INVOKESPECIAL, ownerType.internalName(), name,
			desc.desc(), isInterface);
		return new ObjInv<>(em);
	}

	/**
	 * Emit an {@code invokestatic} instruction
	 * 
	 * @param <SN> the JVM stack at the call site. Some may be popped as arguments
	 * @param <MN> the parameters expected by the method descriptor
	 * @param <MR> the return type from the method descriptor
	 * @param em the emitter
	 * @param ownerType the owner type
	 * @param name the name of the method
	 * @param desc the method descriptor
	 * @param isInterface true to indicate the owner type is an interface
	 * @return an object to complete type checking of the arguments and, if applicable, the result
	 */
	static <
		SN extends Next,
		MN extends Next,
		MR extends BType>
			Inv<MR, SN, MN> invokestatic(Emitter<SN> em, TRef<?> ownerType, String name,
					MthDesc<MR, MN> desc, boolean isInterface) {
		em.mv.visitMethodInsn(Opcodes.INVOKESTATIC, ownerType.internalName(), name,
			desc.desc(), isInterface);
		return new Inv<>(em);
	}

	/**
	 * Emit an {@code invokevirtual} instruction
	 * 
	 * @param <OT> the owner type
	 * @param <SN> the JVM stack at the call site. Some may be popped as arguments
	 * @param <MN> the parameters expected by the method descriptor
	 * @param <MR> the return type from the method descriptor
	 * @param em the emitter
	 * @param ownerType the owner type
	 * @param name the name of the method
	 * @param desc the method descriptor
	 * @param isInterface true to indicate the owner type is an interface
	 * @return an object to complete type checking of the arguments and, if applicable, the result
	 */
	static <OT,
		SN extends Next,
		MN extends Next,
		MR extends BType>
			ObjInv<MR, OT, SN, MN> invokevirtual(Emitter<SN> em, TRef<OT> ownerType, String name,
					MthDesc<MR, MN> desc, boolean isInterface) {
		em.mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, ownerType.internalName(), name,
			desc.desc(), isInterface);
		return new ObjInv<>(em);
	}

	/**
	 * Emit an {@code ior} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> ior(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.IOR);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code irem} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> irem(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.IREM);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ireturn} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param retReq some proof of this method's required return type
	 * @return the dead emitter
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			Emitter<Dead> ireturn(Emitter<N0> em, RetReq<TInt> retReq) {
		em.mv.visitInsn(Opcodes.IRETURN);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ishl} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> ishl(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.ISHL);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ishr} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> ishr(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.ISHR);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code istore} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param local the target local variable
	 * @return the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			Emitter<N1> istore(Emitter<N0> em, Local<TInt> local) {
		em.mv.visitVarInsn(Opcodes.ISTORE, local.index());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code isub} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> isub(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.ISUB);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code iushr} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> iushr(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.IUSHR);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ixor} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> ixor(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.IXOR);
		return (Emitter) em;
	}

	/**
	 * DO NOT emit an {@code jsr} instruction
	 * <p>
	 * According to Oracle's documentation, this deprecated instruction was used in the
	 * implementation of {@code finally} blocks prior to Java SE 6. This method is here only to
	 * guide users searching for the {@code jsr} opcode toward the replacement:
	 * {@link Misc#tryCatch(Emitter, Lbl, Lbl, TRef)}. Syntactically, trying to use this method
	 * should result in all sorts of compilation errors, if not on the invocation itself, then on
	 * anything following it in the chain. At runtime, this <em>always</em> throws an
	 * {@link UnsupportedOperationException}.
	 * 
	 * @param em the emitter
	 * @param target the target label
	 * @return never
	 */
	static Emitter<?> jsr__deprecated(Emitter<?> em, Lbl<?> target) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Emit an {@code l2d} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TLong>>
			Emitter<Ent<N1, TDouble>> l2d(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.L2D);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code l2f} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TLong>>
			Emitter<Ent<N1, TFloat>> l2f(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.L2F);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code l2i} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TLong>>
			Emitter<Ent<N1, TInt>> l2i(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.L2I);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ladd} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TLong>,
		N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TLong>> ladd(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.LADD);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code laload} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., arrayref
	 * @param <N0> ..., arrayref, index
	 * @param em the emitter
	 * @return the emitter with ..., value
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TRef<long[]>>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TLong>> laload(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.LALOAD);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code land} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TLong>,
		N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TLong>> land(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.LAND);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code lastore} instruction
	 * 
	 * @param <N3> the tail of the stack (...)
	 * @param <N2> ..., arrayref
	 * @param <N1> ..., arrayref, index
	 * @param <N0> ..., arrayref, index, value
	 * @param em the emitter
	 * @return the emitter with ...
	 */
	static <
		N3 extends Next,
		N2 extends Ent<N3, TRef<long[]>>,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TLong>>
			Emitter<N3> lastore(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.LASTORE);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code lcmp} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TLong>,
		N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TInt>> lcmp(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.LCMP);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ldc} instruction for an integer
	 * <p>
	 * NOTE: The underlying ASM library may emit alternative instructions at its discretion.
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param value the value to push
	 * @return the emitter with ..., value
	 */
	static <N extends Next>
			Emitter<Ent<N, TInt>> ldc__i(Emitter<N> em, int value) {
		em.mv.visitLdcInsn(value);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ldc} instruction for a long
	 * <p>
	 * NOTE: The underlying ASM library may emit alternative instructions at its discretion.
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param value the value to push
	 * @return the emitter with ..., value
	 */
	static <N extends Next>
			Emitter<Ent<N, TLong>> ldc__l(Emitter<N> em, long value) {
		em.mv.visitLdcInsn(value);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ldc} instruction for a float
	 * <p>
	 * NOTE: The underlying ASM library may emit alternative instructions at its discretion.
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param value the value to push
	 * @return the emitter with ..., value
	 */
	static <N extends Next>
			Emitter<Ent<N, TFloat>> ldc__f(Emitter<N> em, float value) {
		em.mv.visitLdcInsn(value);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ldc} instruction for a double
	 * <p>
	 * NOTE: The underlying ASM library may emit alternative instructions at its discretion.
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param value the value to push
	 * @return the emitter with ..., value
	 */
	static <N extends Next>
			Emitter<Ent<N, TDouble>> ldc__d(Emitter<N> em, double value) {
		em.mv.visitLdcInsn(value);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ldc} instruction for a reference
	 * <p>
	 * NOTE: Only certain reference types are permitted. Some of the permitted types are those
	 * leaked (API-wise) from the underlying ASM library. The underlying ASM library may emit
	 * alternative instructions at its discretion.
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param value the value to push
	 * @return the emitter with ..., value
	 */
	static <T,
		N extends Next>
			Emitter<Ent<N, TRef<T>>> ldc__a(Emitter<N> em, T value) {
		em.mv.visitLdcInsn(value);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ldiv} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TLong>,
		N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TLong>> ldiv(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.LDIV);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code lload} instruction
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param local the handle to the local
	 * @return the emitter with ..., value
	 */
	static <N extends Next>
			Emitter<Ent<N, TLong>> lload(Emitter<N> em, Local<TLong> local) {
		em.mv.visitVarInsn(Opcodes.LLOAD, local.index());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code lmul} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TLong>,
		N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TLong>> lmul(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.LMUL);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code lneg} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TLong>>
			Emitter<Ent<N1, TLong>> lneg(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.LNEG);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code lookupswitch} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., key
	 * @param em the emitter
	 * @param dflt a target label for the default case. The stack at the label must be ...
	 * @param cases a map of integer case value to target label. The stack at each label must be ...
	 * @return the dead emitter
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			Emitter<Dead> lookupswitch(Emitter<N0> em, Lbl<N1> dflt, Map<Integer, Lbl<N1>> cases) {
		em.mv.visitLookupSwitchInsn(dflt.label(),
			cases.keySet().stream().mapToInt(k -> k).toArray(),
			cases.values().stream().map(Lbl::label).toArray(Label[]::new));
		return (Emitter) em;
	}

	/**
	 * Emit an {@code lor} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TLong>,
		N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TLong>> lor(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.LOR);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code lrem} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TLong>,
		N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TLong>> lrem(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.LREM);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code lreturn} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param retReq some proof of this method's required return type
	 * @return the dead emitter
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			Emitter<Dead> lreturn(Emitter<N0> em, RetReq<TInt> retReq) {
		em.mv.visitInsn(Opcodes.LRETURN);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code lshl} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TLong>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TLong>> lshl(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.LSHL);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code lshr} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TLong>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TLong>> lshr(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.LSHR);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code lstore} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param local the target local variable
	 * @return the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TLong>>
			Emitter<N1> lstore(Emitter<N0> em, Local<TLong> local) {
		em.mv.visitVarInsn(Opcodes.LSTORE, local.index());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code lsub} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TLong>,
		N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TLong>> lsub(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.LSUB);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code lushr} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TLong>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TLong>> lushr(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.LUSHR);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code lxor} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value1
	 * @param <N0> ..., value1, value2
	 * @param em the emitter
	 * @return the emitter with ..., result
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TLong>,
		N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TLong>> lxor(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.LXOR);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code monitorenter} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., objectref
	 * @param em the emitter
	 * @return the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TRef<?>>>
			Emitter<N1> monitorenter(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.MONITORENTER);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code monitorexit} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., objectref
	 * @param em the emitter
	 * @return the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TRef<?>>>
			Emitter<N1> monitorexit(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.MONITOREXIT);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code multianewarray} instruction
	 * <p>
	 * NOTE: This will emit the instruction, but derivation of the resulting stack contents is not
	 * implemented. The user must cast the emitter to the resulting type. LATER: If required, we may
	 * implement this for specific dimensions. Or, we might use a pattern similar to what we used
	 * for method invocation to allow us an arbitrary number of stack arguments.
	 * 
	 * @param em the emitter
	 * @param type the type of the full multidimensional array (not just the element type)
	 * @param dimensions the number of dimensions to allocate
	 * @return the emitter with unknown stack
	 */
	static Emitter<?> multianewarray__unsupported(Emitter<?> em, TRef<?> type, int dimensions) {
		em.mv.visitMultiANewArrayInsn(type.internalName(), dimensions);
		return em;
	}

	/**
	 * Emit a {@code new} instruction
	 * 
	 * @param <T> the type of object
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param type the type of object
	 * @return the emitter with ..., objectref (uninitialized)
	 * @implNote We considered using a separate {@code URef} type to indicate an uninitialized
	 *           reference; however, this would fail for the standard {@code new-dup-invokespecial}
	 *           sequence, as the reference remaining on the stack would appear uninitialized when
	 *           it is in fact initialized.
	 */
	static <T extends TRef<?>,
		N extends Next>
			Emitter<Ent<N, T>> new_(Emitter<N> em, T type) {
		em.mv.visitTypeInsn(Opcodes.NEW, type.internalName());
		return (Emitter) em;
	}

	/**
	 * Emit a {@code newarray} instruction
	 * 
	 * @param <AT> the resulting array type
	 * @param <ET> the (primitive) element type
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., count
	 * @param em the emitter
	 * @param elemType the element type
	 * @return the emitter with ..., arrayref
	 */
	static <AT, ET extends SPrim<AT>,
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N1, TRef<AT>>> newarray(Emitter<N0> em, ET elemType) {
		em.mv.visitIntInsn(Opcodes.NEWARRAY, elemType.t());
		return (Emitter) em;
	}

	/**
	 * Emit a {@code nop} instruction
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @return the emitter with ...
	 */
	static <N extends Next>
			Emitter<N> nop(Emitter<N> em) {
		em.mv.visitInsn(Opcodes.NOP);
		return em;
	}

	/**
	 * Emit a {@code pop} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @return the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, ? extends TCat1>>
			Emitter<N1> pop(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.POP);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code pop2} instruction to pop two operands (Form 1)
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value2
	 * @param <N0> ..., value2, value1
	 * @param em the emitter
	 * @return the emitter with ...
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, ? extends TCat1>,
		N0 extends Ent<N1, ? extends TCat1>>
			Emitter<N2> pop2__11(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.POP2);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code pop2} instruction to pop one operand (Form 2)
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value1
	 * @param em the emitter
	 * @return the emitter with ...
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, ? extends TCat2>>
			Emitter<N1> pop2__2(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.POP2);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code putfield} instruction
	 * 
	 * @param <OT> the owner type
	 * @param <T2> the type of the object on the stack owning the field
	 * @param <FT> the type of the field
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., objectref
	 * @param <N0> ..., objectref, value
	 * @param em the emitter
	 * @param owner the owner type
	 * @param name the name of the field
	 * @param type the type of the field
	 * @return the emitter with ...
	 */
	static <OT, T2 extends TRef<? extends OT>, FT extends BNonVoid,
		N2 extends Next,
		N1 extends Ent<N2, T2>,
		N0 extends Ent<N1, ? extends FT>>
			Emitter<N2> putfield(Emitter<N0> em, TRef<OT> owner, String name,
					FT type) {
		em.mv.visitFieldInsn(Opcodes.PUTFIELD, owner.internalName(), name,
			type.type().getDescriptor());
		return (Emitter) em;
	}

	/**
	 * Emit a {@code putstatic} instruction
	 * 
	 * @param <FT> the type of the field
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., value
	 * @param em the emitter
	 * @param owner the owner type
	 * @param name the name of the field
	 * @param type the type of the field
	 * @return the emitter with ...
	 */
	static <FT extends BNonVoid,
		N1 extends Next,
		N0 extends Ent<N1, ? extends FT>>
			Emitter<N1> putstatic(Emitter<N0> em, TRef<?> owner, String name,
					FT type) {
		em.mv.visitFieldInsn(Opcodes.PUTSTATIC, owner.internalName(), name,
			type.type().getDescriptor());
		return (Emitter) em;
	}

	/**
	 * DO NOT emit an {@code ret} instruction
	 * <p>
	 * According to Oracle's documentation, this deprecated instruction was used in the
	 * implementation of {@code finally} blocks prior to Java SE 6. You may actually be searching
	 * for the {@link #return_(Emitter, RetReq)} method. This method is here only to guide users
	 * searching for the {@code ret} opcode toward the replacement:
	 * {@link Misc#tryCatch(Emitter, Lbl, Lbl, TRef)}. Syntactically, trying to use this method
	 * should result in all sorts of compilation errors, if not on the invocation itself, then on
	 * anything following it in the chain. At runtime, this <em>always</em> throws an
	 * {@link UnsupportedOperationException}.
	 * 
	 * @param em the emitter
	 * @param local the local variable (NOTE: {@code returnAddress} is not a supported type)
	 * @return never
	 */
	static Emitter<?> ret__deprecated(Emitter<?> em, Local<?> local) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Emit a {@code return} instruction
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param retReq some proof of this method's required return type
	 * @return the dead emitter
	 */
	static <N extends Next>
			Emitter<Dead> return_(Emitter<N> em, RetReq<TVoid> retReq) {
		em.mv.visitInsn(Opcodes.RETURN);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code saload} instruction
	 * 
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., arrayref
	 * @param <N0> ..., arrayref, index
	 * @param em the emitter
	 * @return the emitter with ..., value
	 */
	static <
		N2 extends Next,
		N1 extends Ent<N2, TRef<short[]>>,
		N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> saload(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.SALOAD);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code sastore} instruction
	 * 
	 * @param <N3> the tail of the stack (...)
	 * @param <N2> ..., arrayref
	 * @param <N1> ..., arrayref, index
	 * @param <N0> ..., arrayref, index, value
	 * @param em the emitter
	 * @return the emitter with ...
	 */
	static <
		N3 extends Next,
		N2 extends Ent<N3, TRef<short[]>>,
		N1 extends Ent<N2, TInt>,
		N0 extends Ent<N1, TInt>>
			Emitter<N3> sastore(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.SASTORE);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code swap} instruction
	 * 
	 * @param <T2> the type of value2 on the stack
	 * @param <T1> the type of value1 on the stack
	 * @param <N2> the tail of the stack (...)
	 * @param <N1> ..., value2
	 * @param <N0> ..., value2, value1
	 * @param em the emitter
	 * @return the emitter with ..., value1, value2
	 */
	static <T2 extends TCat1, T1 extends TCat1,
		N2 extends Next, N1 extends Ent<N2, T2>,
		N0 extends Ent<N1, T1>>
			Emitter<Ent<Ent<N2, T1>, T2>> swap(Emitter<N0> em) {
		em.mv.visitInsn(Opcodes.SWAP);
		return (Emitter) em;
	}

	/**
	 * Emit a {@code tableswitch} instruction
	 * 
	 * @param <N1> the tail of the stack (...)
	 * @param <N0> ..., index
	 * @param em the emitter
	 * @param low the low index
	 * @param dflt a target label for the default case. The stack at the label must be ...
	 * @param cases a list of target labels. The stack at each label must be ...
	 * @return the dead emitter
	 */
	static <
		N1 extends Next,
		N0 extends Ent<N1, TInt>>
			Emitter<Dead> tableswitch(Emitter<N0> em, int low, Lbl<N1> dflt, List<Lbl<N1>> cases) {
		int high = low + cases.size() - 1; // inclusive
		em.mv.visitTableSwitchInsn(low, high, dflt.label(),
			cases.stream().map(Lbl::label).toArray(Label[]::new));
		return (Emitter) em;
	}
}
