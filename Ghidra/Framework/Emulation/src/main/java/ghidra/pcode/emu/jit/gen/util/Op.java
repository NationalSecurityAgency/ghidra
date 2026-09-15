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

import java.lang.classfile.CodeBuilder;
import java.lang.classfile.instruction.SwitchCase;
import java.lang.constant.*;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.Function;

import ghidra.pcode.emu.jit.JitCompiler;
import ghidra.pcode.emu.jit.JitCompiler.Diag;
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
	boolean DEEP_TRACE = JitCompiler.ENABLE_DIAGNOSTICS.contains(Diag.DEEP_TRACE);

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
		if (DEEP_TRACE) {
			System.err.println("    jvm: aaload");
		}
		em.cb.aaload();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: aastore");
		}
		em.cb.aastore();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: aconst_null     %s".formatted(type));
		}
		em.cb.aconst_null();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: aload           %s".formatted(local));
		}
		em.cb.aload(local.index());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: anewarray       %s".formatted(elemType));
		}
		em.cb.anewarray(elemType.classDesc());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: areturn         %s".formatted(retReq));
		}
		em.cb.areturn();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: arraylength     %s".formatted(elemType));
		}
		em.cb.arraylength();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: arraylength");
		}
		em.cb.arraylength();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: astore          %s".formatted(local));
		}
		em.cb.astore(local.index());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: athrow");
		}
		em.cb.athrow();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: baload");
		}
		em.cb.baload();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: baload");
		}
		em.cb.baload();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: bastore");
		}
		em.cb.bastore();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: bastore");
		}
		em.cb.bastore();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: caload");
		}
		em.cb.caload();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: castore");
		}
		em.cb.castore();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: checkcast       %s".formatted(type));
		}
		em.cb.checkcast(type.classDesc());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: d2f");
		}
		em.cb.d2f();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: d2i");
		}
		em.cb.d2i();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: d2l");
		}
		em.cb.d2l();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dadd");
		}
		em.cb.dadd();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: daload");
		}
		em.cb.daload();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dastore");
		}
		em.cb.dastore();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dcmpg");
		}
		em.cb.dcmpg();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dcmpl");
		}
		em.cb.dcmpl();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: ddiv");
		}
		em.cb.ddiv();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dload           %s".formatted(local));
		}
		em.cb.dload(local.index());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dmul");
		}
		em.cb.dmul();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dneg");
		}
		em.cb.dneg();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: drem");
		}
		em.cb.drem();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dreturn         %s".formatted(retReq));
		}
		em.cb.dreturn();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dstore          %s".formatted(local));
		}
		em.cb.dstore(local.index());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dsub");
		}
		em.cb.dsub();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dup");
		}
		em.cb.dup();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dup_x1");
		}
		em.cb.dup_x1();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dup_x2 (111)");
		}
		em.cb.dup_x2();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dup_x2 (21)");
		}
		em.cb.dup_x2();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dup2 (11)");
		}
		em.cb.dup2();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dup2 (2)");
		}
		em.cb.dup2();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dup2_x1 (111)");
		}
		em.cb.dup2_x1();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dup2_x1 (12)");
		}
		em.cb.dup2_x1();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dup2_x2 (1111)");
		}
		em.cb.dup2_x2();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dup2_x2 (112)");
		}
		em.cb.dup2_x2();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dup2_x2 (211)");
		}
		em.cb.dup2_x2();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: dup2_x2 (22)");
		}
		em.cb.dup2_x2();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: f2d");
		}
		em.cb.f2d();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: f2i");
		}
		em.cb.f2i();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: f2l");
		}
		em.cb.f2l();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: fadd");
		}
		em.cb.fadd();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: faload");
		}
		em.cb.faload();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: fastore");
		}
		em.cb.fastore();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: fcmpg");
		}
		em.cb.fcmpg();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: fcmpl");
		}
		em.cb.fcmpl();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: fdiv");
		}
		em.cb.fdiv();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: fload           %s".formatted(local));
		}
		em.cb.fload(local.index());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: fmul");
		}
		em.cb.fmul();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: fneg");
		}
		em.cb.fneg();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: frem");
		}
		em.cb.frem();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: freturn         %s".formatted(retReq));
		}
		em.cb.freturn();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: fstore          %s".formatted(local));
		}
		em.cb.fstore(local.index());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: fsub");
		}
		em.cb.fsub();
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
		if (DEEP_TRACE) {
			System.err.println("""
					\
					    jvm: getfield        %s %s
					                         .%s""".formatted(type, owner, name));
		}
		em.cb.getfield(owner.classDesc(), name, type.classDesc());
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
		if (DEEP_TRACE) {
			System.err.println("""
					\
					    jvm: getstatic       %s %s
					                         .%s""".formatted(type, owner, name));
		}
		em.cb.getstatic(owner.classDesc(), name, type.classDesc());
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
		Lbl<N> target = Lbl.create(em);
		if (DEEP_TRACE) {
			System.err.println("    jvm: goto            %s".formatted(target));
		}
		em.cb.goto_(target.label());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: goto            %s".formatted(target));
		}
		em.cb.goto_(target.label());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: i2b");
		}
		em.cb.i2b();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: i2c");
		}
		em.cb.i2c();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: i2d");
		}
		em.cb.i2d();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: i2f");
		}
		em.cb.i2f();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: i2l");
		}
		em.cb.i2l();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: i2s");
		}
		em.cb.i2s();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: iadd");
		}
		em.cb.iadd();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: iaload");
		}
		em.cb.iaload();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: iand");
		}
		em.cb.iand();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: iastore");
		}
		em.cb.iastore();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: idiv");
		}
		em.cb.idiv();
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
		Lbl<N2> target = Lbl.create(em);
		if (DEEP_TRACE) {
			System.err.println("    jvm: if_acmpeq       %s".formatted(target));
		}
		em.cb.if_acmpeq(target.label());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: if_acmpeq       %s".formatted(target));
		}
		em.cb.if_acmpeq(target.label());
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
		Lbl<N2> target = Lbl.create(em);
		if (DEEP_TRACE) {
			System.err.println("    jvm: if_acmpne       %s".formatted(target));
		}
		em.cb.if_acmpne(target.label());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: if_acmpne       %s".formatted(target));
		}
		em.cb.if_acmpne(target.label());
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
		Lbl<N2> target = Lbl.create(em);
		if (DEEP_TRACE) {
			System.err.println("    jvm: if_icmpeq       %s".formatted(target));
		}
		em.cb.if_icmpeq(target.label());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: if_icmpeq       %s".formatted(target));
		}
		em.cb.if_icmpeq(target.label());
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
		Lbl<N2> target = Lbl.create(em);
		if (DEEP_TRACE) {
			System.err.println("    jvm: if_icmpge       %s".formatted(target));
		}
		em.cb.if_icmpge(target.label());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: if_icmpge       %s".formatted(target));
		}
		em.cb.if_icmpge(target.label());
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
		Lbl<N2> target = Lbl.create(em);
		if (DEEP_TRACE) {
			System.err.println("    jvm: if_icmpgt       %s".formatted(target));
		}
		em.cb.if_icmpgt(target.label());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: if_icmpgt       %s".formatted(target));
		}
		em.cb.if_icmpgt(target.label());
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
		Lbl<N2> target = Lbl.create(em);
		if (DEEP_TRACE) {
			System.err.println("    jvm: if_icmple       %s".formatted(target));
		}
		em.cb.if_icmple(target.label());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: if_icmple       %s".formatted(target));
		}
		em.cb.if_icmple(target.label());
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
		Lbl<N2> target = Lbl.create(em);
		if (DEEP_TRACE) {
			System.err.println("    jvm: if_icmplt       %s".formatted(target));
		}
		em.cb.if_icmplt(target.label());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: if_icmplt       %s".formatted(target));
		}
		em.cb.if_icmplt(target.label());
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
		Lbl<N2> target = Lbl.create(em);
		if (DEEP_TRACE) {
			System.err.println("    jvm: if_icmpne       %s".formatted(target));
		}
		em.cb.if_icmpne(target.label());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: if_icmpne       %s".formatted(target));
		}
		em.cb.if_icmpne(target.label());
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
		Lbl<N1> target = Lbl.create(em);
		if (DEEP_TRACE) {
			System.err.println("    jvm: ifeq            %s".formatted(target));
		}
		em.cb.ifeq(target.label());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: ifeq            %s".formatted(target));
		}
		em.cb.ifeq(target.label());
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
		Lbl<N1> target = Lbl.create(em);
		if (DEEP_TRACE) {
			System.err.println("    jvm: ifge            %s".formatted(target));
		}
		em.cb.ifge(target.label());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: ifge            %s".formatted(target));
		}
		em.cb.ifge(target.label());
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
		Lbl<N1> target = Lbl.create(em);
		if (DEEP_TRACE) {
			System.err.println("    jvm: ifgt            %s".formatted(target));
		}
		em.cb.ifgt(target.label());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: ifgt            %s".formatted(target));
		}
		em.cb.ifgt(target.label());
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
		Lbl<N1> target = Lbl.create(em);
		if (DEEP_TRACE) {
			System.err.println("    jvm: ifle            %s".formatted(target));
		}
		em.cb.ifle(target.label());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: ifle            %s".formatted(target));
		}
		em.cb.ifle(target.label());
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
		Lbl<N1> target = Lbl.create(em);
		if (DEEP_TRACE) {
			System.err.println("    jvm: iflt            %s".formatted(target));
		}
		em.cb.iflt(target.label());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: iflt            %s".formatted(target));
		}
		em.cb.iflt(target.label());
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
		Lbl<N1> target = Lbl.create(em);
		if (DEEP_TRACE) {
			System.err.println("    jvm: ifne            %s".formatted(target));
		}
		em.cb.ifne(target.label());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: ifne            %s".formatted(target));
		}
		em.cb.ifne(target.label());
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
		Lbl<N1> target = Lbl.create(em);
		if (DEEP_TRACE) {
			System.err.println("    jvm: ifnonnull       %s".formatted(target));
		}
		em.cb.ifnonnull(target.label());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: ifnonnull       %s".formatted(target));
		}
		em.cb.ifnonnull(target.label());
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
		Lbl<N1> target = Lbl.create(em);
		if (DEEP_TRACE) {
			System.err.println("    jvm: ifnull          %s".formatted(target));
		}
		em.cb.ifnull(target.label());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: ifnull          %s".formatted(target));
		}
		em.cb.ifnull(target.label());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: iinc            %s %d".formatted(local, increment));
		}
		em.cb.iinc(local.index(), increment);
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: iload           %s".formatted(local));
		}
		em.cb.iload(local.index());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: imul");
		}
		em.cb.imul();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: ineg");
		}
		em.cb.ineg();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: instanceof      %s".formatted(type));
		}
		em.cb.instanceOf(type.classDesc());
		return (Emitter) em;
	}

	/**
	 * Emit an {@code invokedynamic} instruction
	 * <p>
	 * <b>WARNING:</b> This is probably not implemented correctly. The JVM spec does not provide an
	 * example, but the best we can tell, after all the call site resolution machinery, the net
	 * arguments actually consumed from the stack is determined by the given method descriptor. We
	 * also just let the Class-File API types {@link DirectMethodHandleDesc}, {@link ConstantDesc},
	 * and {@link DynamicCallSiteDesc} leak from an API perspective.
	 *
	 * @param <SN> the JVM stack at the call site. Some may be popped as arguments
	 * @param <MN> the parameters expected by the method descriptor
	 * @param <MR> the return type from the method descriptor
	 * @param em the emitter
	 * @param name the name of the method
	 * @param desc the method descriptor
	 * @param bootstrapMethodHandle as in {@link CodeBuilder#invokedynamic}
	 * @param bootstrapMethodArguments as in {@link CodeBuilder#invokedynamic}
	 * @return an object to complete type checking of the arguments and, if applicable, the result
	 */
	static <
		SN extends Next,
		MN extends Next,
		MR extends BType>
			Inv<MR, SN, MN> invokedynamic__unsupported(Emitter<SN> em, String name,
					MthDesc<MR, MN> desc, DirectMethodHandleDesc bootstrapMethodHandle,
					ConstantDesc... bootstrapMethodArguments) {
		if (DEEP_TRACE) {
			System.err.println("""
					\
					    jvm: invokedynamic   %s %s %s %s""".formatted(name, desc,
				bootstrapMethodHandle, bootstrapMethodArguments));
		}
		em.cb.invokedynamic(DynamicCallSiteDesc.of(
			bootstrapMethodHandle, name, desc.desc(), bootstrapMethodArguments));
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
		if (DEEP_TRACE) {
			System.err.println("""
					\
					    jvm: invokeinterface %s
					                         .%s %s""".formatted(ownerType, name, desc));
		}
		em.cb.invokeinterface(ownerType.classDesc(), name, desc.desc());
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
		if (DEEP_TRACE) {
			System.err.println("""
					\
					    jvm: invokespecial   %s
					                         .%s %s (%s)""".formatted(ownerType, name, desc,
				isInterface ? "interface" : "class"));
		}
		em.cb.invokespecial(ownerType.classDesc(), name, desc.desc(), isInterface);
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
		if (DEEP_TRACE) {
			System.err.println("""
					\
					    jvm: invokestatic    %s
					                         .%s %s (%s)""".formatted(ownerType, name, desc,
				isInterface ? "interface" : "class"));
		}
		em.cb.invokestatic(ownerType.classDesc(), name, desc.desc(), isInterface);
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
		if (DEEP_TRACE) {
			System.err.println("""
					\
					    jvm: invokevirtual   %s
					                         .%s %s (%s)""".formatted(ownerType, name, desc,
				isInterface ? "interface" : "class"));
		}
		em.cb.invokevirtual(ownerType.classDesc(), name, desc.desc());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: ior");
		}
		em.cb.ior();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: irem");
		}
		em.cb.irem();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: ireturn         %s".formatted(retReq));
		}
		em.cb.ireturn();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: ishl");
		}
		em.cb.ishl();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: ishr");
		}
		em.cb.ishr();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: istore          %s".formatted(local));
		}
		em.cb.istore(local.index());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: isub");
		}
		em.cb.isub();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: iushr");
		}
		em.cb.iushr();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: ixor");
		}
		em.cb.ixor();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: l2d");
		}
		em.cb.l2d();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: l2f");
		}
		em.cb.l2f();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: l2i");
		}
		em.cb.l2i();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: ladd");
		}
		em.cb.ladd();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: laload");
		}
		em.cb.laload();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: land");
		}
		em.cb.land();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: lastore");
		}
		em.cb.lastore();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: lcmp");
		}
		em.cb.lcmp();
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ldc} instruction for an integer
	 * <p>
	 * NOTE: The underlying Class-File API may emit alternative instructions at its discretion.
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param value the value to push
	 * @return the emitter with ..., value
	 */
	static <N extends Next>
			Emitter<Ent<N, TInt>> ldc__i(Emitter<N> em, int value) {
		if (DEEP_TRACE) {
			System.err.println("    jvm: ldc (int)       0x%x %d".formatted(value, value));
		}
		em.cb.loadConstant(value);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ldc} instruction for a long
	 * <p>
	 * NOTE: The underlying Class-File API may emit alternative instructions at its discretion.
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param value the value to push
	 * @return the emitter with ..., value
	 */
	static <N extends Next>
			Emitter<Ent<N, TLong>> ldc__l(Emitter<N> em, long value) {
		if (DEEP_TRACE) {
			System.err.println("    jvm: ldc (long)      0x%x %d".formatted(value, value));
		}
		em.cb.loadConstant(value);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ldc} instruction for a float
	 * <p>
	 * NOTE: The underlying Class-File API may emit alternative instructions at its discretion.
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param value the value to push
	 * @return the emitter with ..., value
	 */
	static <N extends Next>
			Emitter<Ent<N, TFloat>> ldc__f(Emitter<N> em, float value) {
		if (DEEP_TRACE) {
			System.err.println("    jvm: ldc (float)     %s".formatted(value));
		}
		em.cb.loadConstant(value);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ldc} instruction for a double
	 * <p>
	 * NOTE: The underlying Class-File API may emit alternative instructions at its discretion.
	 * 
	 * @param <N> the tail of the stack (...)
	 * @param em the emitter
	 * @param value the value to push
	 * @return the emitter with ..., value
	 */
	static <N extends Next>
			Emitter<Ent<N, TDouble>> ldc__d(Emitter<N> em, double value) {
		if (DEEP_TRACE) {
			System.err.println("    jvm: ldc (double)    %s".formatted(value));
		}
		em.cb.loadConstant(value);
		return (Emitter) em;
	}

	/**
	 * Emit an {@code ldc} instruction for a reference
	 * <p>
	 * NOTE: Only certain reference types are permitted. The underlying Class-File API may emit
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: ldc             (%s) %s"
					.formatted(value.getClass().getSimpleName(), value));
		}
		// value must implement ConstantDesc. T is the runtime type on the stack, which
		// for String constants is the same as the ConstantDesc type.
		em.cb.loadConstant((ConstantDesc) value);
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: ldiv");
		}
		em.cb.ldiv();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: lload           %s".formatted(local));
		}
		em.cb.lload(local.index());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: lmul");
		}
		em.cb.lmul();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: lneg");
		}
		em.cb.lneg();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: lookupswitch    default=%s, cases={".formatted(dflt));
			for (Entry<Integer, Lbl<N1>> ent : cases.entrySet()) {
				System.err.println("           %d: %s".formatted(ent.getKey(), ent.getValue()));
			}
			System.err.println("         }");
		}
		em.cb.lookupswitch(dflt.label(),
			cases.entrySet()
					.stream()
					.map(e -> SwitchCase.of(e.getKey(), e.getValue().label()))
					.toList());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: lor");
		}
		em.cb.lor();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: lrem");
		}
		em.cb.lrem();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: lreturn         %s".formatted(retReq));
		}
		em.cb.lreturn();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: lshl");
		}
		em.cb.lshl();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: lshr");
		}
		em.cb.lshr();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: lstore          %s".formatted(local));
		}
		em.cb.lstore(local.index());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: lsub");
		}
		em.cb.lsub();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: lushr");
		}
		em.cb.lushr();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: lxor");
		}
		em.cb.lxor();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: monitorenter");
		}
		em.cb.monitorenter();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: monitorexit");
		}
		em.cb.monitorexit();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: multianewarray  %s %s".formatted(type, dimensions));
		}
		em.cb.multianewarray(type.classDesc(), dimensions);
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: new             %s".formatted(type));
		}
		em.cb.new_(type.classDesc());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: newarray        %s".formatted(elemType));
		}
		em.cb.newarray(elemType.typeKind());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: nop");
		}
		em.cb.nop();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: pop");
		}
		em.cb.pop();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: pop2 (11)");
		}
		em.cb.pop2();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: pop2 (2)");
		}
		em.cb.pop2();
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
			Emitter<N2> putfield(Emitter<N0> em, TRef<OT> owner, String name, FT type) {
		if (DEEP_TRACE) {
			System.err.println("""
					\
					    jvm: putfield        %s %s
					                         .%s""".formatted(type, owner, name));
		}
		em.cb.putfield(owner.classDesc(), name, type.classDesc());
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
			Emitter<N1> putstatic(Emitter<N0> em, TRef<?> owner, String name, FT type) {
		if (DEEP_TRACE) {
			System.err.println("""
					\
					    jvm: putstatic       %s %s
					                         .%s""".formatted(type, owner, name));
		}
		em.cb.putstatic(owner.classDesc(), name, type.classDesc());
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: return          %s".formatted(retReq));
		}
		em.cb.return_();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: saload");
		}
		em.cb.saload();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: sastore");
		}
		em.cb.sastore();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: swap");
		}
		em.cb.swap();
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
		if (DEEP_TRACE) {
			System.err.println("    jvm: tableswitch     default=%s cases=[".formatted(dflt));
			for (int i = 0; i < cases.size(); i++) {
				System.err.println("           %d: %s".formatted(i, cases.get(i)));
			}
			System.err.println("         ]");
		}
		List<SwitchCase> switchCases = new ArrayList<>();
		for (int i = 0; i < cases.size(); i++) {
			switchCases.add(SwitchCase.of(low + i, cases.get(i).label()));
		}
		em.cb.tableswitch(dflt.label(), switchCases);
		return (Emitter) em;
	}
}
