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

import java.lang.System.Logger.Level;

import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Types.BNonVoid;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;

/**
 * Miscellaneous utilities
 */
@SuppressWarnings({ "unchecked", "rawtypes" })
public interface Misc {

	/**
	 * Fix the top of the stack, so it doesn't "extend" {@link Ent}, but just is {@link Ent}.
	 * <p>
	 * This may be necessary when a code generating method is typed to pop then push something of
	 * the same type, but in some conditions actually just leaves the stack as is.
	 * 
	 * @param <T1> the type at the top of the stack
	 * @param <N1> the tail of the stack
	 * @param <N0> the full stack
	 * @param em the emitter
	 * @return the same emitter
	 */
	static <T1 extends BNonVoid,
		N1 extends Next,
		N0 extends Ent<N1, T1>>
			Emitter<Ent<N1, T1>> cast1(Emitter<N0> em) {
		return (Emitter) em;
	}

	/**
	 * A handle to an (incomplete) {@code try-catch} block
	 * 
	 * @param <T> the type caught by the block
	 * @param <N> the stack contents at the start and end of the {@code try} block
	 * @param end the label to place at the end of the {@code try} block
	 * @param handler the label to place at the handler, i.e., the start of the {@code catch} block.
	 *            Note that the stack is the same as the block bounds, but with the exception type
	 *            pushed. FIXME: Is that fully correct? Do we know what's actually underneath the
	 *            exception?
	 * @param em the emitter at the start of the {@code try} block
	 */
	record TryCatchBlock<T extends Throwable, N extends Next>(Lbl<N> end,
			Lbl<Ent<N, TRef<T>>> handler, Emitter<N> em) {}

	/**
	 * Start a try-catch block
	 * <p>
	 * This places a label to mark the start of the {@code try} block. The user must provide labels
	 * for the end and the handler. Note that the stack contents at the handler must be the same as
	 * at the bounds, but with the exception type pushed. While this can check that the labels are
	 * correctly placed, it cannot check if placement is altogether forgotten. Ideally, the handler
	 * label is placed where code is otherwise unreachable, i.e., using
	 * {@code Lbl#placeDead(Emitter, Lbl)}.
	 * 
	 * @param <T> the type caught by the block
	 * @param <N> the stack contents at the bounds of the {@code try} block
	 * @param em the emitter
	 * @param end the end label, often just {@link Lbl#create()}.
	 * @param handler the handler label, often just {@link Lbl#create()}
	 * @param type the exception type. If multiple types are caught, this must be the join of those
	 *            types, and the user must emit code to distinguish each, possibly re-throwing if
	 *            the join is larger than the union.
	 * @return a handle to the block.
	 */
	static <T extends Throwable, N extends Next> TryCatchBlock<T, N> tryCatch(Emitter<N> em,
			Lbl<N> end, Lbl<Ent<N, TRef<T>>> handler, TRef<T> type) {
		Lbl<N> start = Lbl.create();
		em = em.emit(Lbl::place, start);
		em.mv.visitTryCatchBlock(start.label(), end.label(), handler.label(),
			type.internalName());
		return new TryCatchBlock<>(end, handler, em);
	}

	/**
	 * Place a line number
	 * 
	 * @param <N> any live stack
	 * @param em the emitter
	 * @param number the (non zero) line number
	 * @return the emitter
	 */
	static <N extends Next> Emitter<N> lineNumber(Emitter<N> em, int number) {
		Label label = new Label();
		em.mv.visitLabel(label);
		em.mv.visitLineNumber(number, label);
		return em;
	}

	/**
	 * Finish emitting bytecode
	 * <p>
	 * This is where we invoke {@link MethodVisitor#visitMaxs(int, int)}. Frameworks that require
	 * bytecode generation can try to enforce this by requiring bytecode generation methods to
	 * return {@link Void}. Sure, a user can just return null, but this will at least remind them
	 * that they should call this method, as convention is to use a pattern like:
	 * 
	 * <pre>
	 * return em
	 * 		.emit(Op::ldc__i, 0)
	 * 		.emit(Op::ireturn, retReq)
	 * 		.emit(Misc::finish);
	 * </pre>
	 * <p>
	 * A user of this pattern would be reminded were {@code finish} missing. Provided the generation
	 * method returns {@link Void}, this pattern should compile.
	 * 
	 * @param em the emittter
	 * @return null
	 */
	static Void finish(Emitter<Dead> em) {
		em.rootScope.close();
		try {
			em.mv.visitMaxs(0, 0);
		}
		catch (Exception e) {
			Emitter.LOGGER.log(Level.WARNING, "Failed to compute Maxs", e);
		}
		em.mv.visitEnd();
		return null;
	}
}
