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

import org.objectweb.asm.Label;

import ghidra.pcode.emu.jit.gen.util.Emitter.Dead;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Methods.RetReq;

/**
 * Utility for defining and placing labels.
 * <p>
 * These are used as control-flow targets, to specify the scope of local variables, and to specify
 * the bounds of {@code try-catch} blocks.
 * <p>
 * Labels, and the possibility of control flow, necessitate some care when trying to validate stack
 * contents in generated code. Again, our goal is to find an acceptable syntax that also provides as
 * much flexibility as possible for later maintenance and refactoring. The requirements:
 * <ul>
 * <li>Where code can jump, the stack at the jump target must agree with the resulting stack at the
 * jump site.</li>
 * <li>If code is only reachable by a jump, then the stack there must be the resulting stack at the
 * jump site.</li>
 * <li>If code is reachable by multiple jumps and/or fall-through, then the stack must agree along
 * all those paths.</li>
 * </ul>
 * <p>
 * To enforce these requirements, we encode thhe stack contents at a label's position in the same
 * manner as we encode the emitter's current stack contents. Now, when a label is placed, there are
 * two possibilities: 1) The code is reachable, in which case the label's and the emitter's stacks
 * must agree. 2) The code is unreachable, in which case the emitter's incoming stack does not
 * matter. Its resulting stack is the label's stack, and the code at this point is now presumed
 * reachable. Because we would have collisions due to type erasure, these two cases are implemented
 * in non-overloaded methods {@link #place(Emitter, Lbl)} and {@link #placeDead(Emitter, Lbl)}.
 * <p>
 * As an example, we show an {@code if-else} construct:
 * 
 * <pre>
 * var lblLess = em
 * 		.emit(Op::iload, params.a)
 * 		.emit(Op::ldc__i, 20)
 * 		.emit(Op::if_icmple);
 * var lblDone = lblLess.em()
 * 		.emit(Op::ldc__i, 0xcafe)
 * 		.emit(Op::goto_);
 * return lblDone.em()
 * 		.emit(Lbl::placeDead, lblLess.lbl())
 * 		.emit(Op::ldc__i, 0xbabe)
 * 		.emit(Lbl::place, lblDone.lbl())
 * 		.emit(Op::ireturn, retReq);
 * </pre>
 * <p>
 * This would be equivalent to
 * 
 * <pre>
 * int myFunc(int a) {
 * 	if (a &lt;= 20) {
 * 		return 0xbabe;
 * 	}
 * 	else {
 * 		return 0xcafe;
 * 	}
 * }
 * </pre>
 * <p>
 * Note that we allow the Java compiler to infer the type of the label targeted by the
 * {@link Op#if_icmple(Emitter)}. That form of the operator generates a label for us, and the
 * inferred type of {@code lblLess} is an {@link LblEm}{@code <Bot>}, representing the empty stack,
 * because the conditional jump consumes both ints without pushing anything. The emitter in that
 * returned tuple has the same stack contents, representing the fall-through case, and so we emit
 * code into the false branch. To avoid falling through into the true branch, we emit an
 * unconditional jump, i.e., {@link Op#goto_(Emitter)}, again taking advantage of Java's type
 * inference to automatically derive the stack contents. Similar to the previous jump instruction,
 * this returns a tuple, but this time, while the label still expects an empty stack, the emitter
 * now has {@code <N>:=}{@link Dead}, because any code emitted after this point would be
 * unreachable. It is worth noting that <em>none</em> of the methods in {@link Op} accept a dead
 * emitter. The only way (don't you dare cast it!) to resurrect the emitter is to place a label
 * using {@link #placeDead(Emitter, Lbl)}. This is fitting, since we need to emit the true branch,
 * so we place {@code lblLess} and emit the appropriate code. There is no need to jump after the
 * true branch. We just allow both branches to flow into the same
 * {@link Op#ireturn(Emitter, RetReq)}. Thus, we place {@code lblDone}, which is checked by the Java
 * compiler to have matching stack contents, and finally emit the return.
 * <p>
 * There is some manual bookkeeping here to ensure we use each previous emitter, but this is not too
 * much worse than the manual bookkeeping needed to track label placement. In our experience, when
 * we get that wrong, the compiler reports it as inconsistent, anyway. One drawback to using type
 * inference is that the label's name does not appear in the jump instruction that targets it. We do
 * not currently have a solution to that complaint.
 * 
 * @param <N> the stack contents where the label is placed (or must be placed)
 * @param label the wrapped ASM label
 */
public record Lbl<N extends Next>(Label label) {
	/**
	 * A tuple providing both a (new) label and a resulting emitter
	 * 
	 * @param <LN> the label's stack contents
	 * @param <N> the emitter's stack contents, which will be the same as the label's, unless it is
	 *            {@link Dead}.
	 * @param lbl the label
	 * @param em the emitter
	 */
	public record LblEm<LN extends Next, N>(Lbl<LN> lbl, Emitter<N> em) {}

	/**
	 * Create a fresh label with any expected stack contents
	 * <p>
	 * Using this to forward declare labels requires the user to explicate the expected stack, which
	 * may not be ideal, as it may require updating during refactoring. Consider using
	 * {@link Lbl#place(Emitter)} instead, which facilitates inference of the stack contents.
	 * 
	 * @param <N> the expected stack contents
	 * @return the label
	 */
	public static <N extends Next> Lbl<N> create() {
		return new Lbl<>(new Label());
	}

	/**
	 * Generate a place a label where execution could already reach
	 * <p>
	 * The returned label's stack will match this emitter's stack, since the code could be reached
	 * by multiple paths, likely fall-through and a jump to the returned label.
	 * 
	 * @param <N> the emitter's and the label's stack, i.e., as where the returned label is
	 *            referenced
	 * @param em the emitter
	 * @return the label and emitter
	 */
	public static <N extends Next> LblEm<N, N> place(Emitter<N> em) {
		Lbl<N> lbl = create();
		em.mv.visitLabel(lbl.label);
		return new LblEm<>(lbl, em);
	}

	/**
	 * Place the given label at a place where execution could already reach
	 * <p>
	 * The emitter's stack and the label's stack must agree, since the code is reachable by multiple
	 * paths, likely fallthrough and a jump to the given label.
	 * 
	 * @param <N> the emitter's and the label's stack, i.e., as where the given label is referenced
	 * @param em the emitter
	 * @param lbl the label to place
	 * @return the same emitter
	 */
	public static <N extends Next> Emitter<N> place(Emitter<N> em, Lbl<N> lbl) {
		em.mv.visitLabel(lbl.label);
		return em;
	}

	/**
	 * Place the given label at a place where execution could not otherwise reach
	 * <p>
	 * The emitter must be dead, i.e., if it were to emit code, that code would be unreachable. By
	 * placing a referenced label at this place, the code following becomes reachable, and so the
	 * given emitter becomes alive again, having the stack that results from the referenced code. If
	 * the label has not yet been referenced, it must be forward declared with the expected stack.
	 * There is no equivalent of {@link #place(Emitter)} for a dead emitter, because there is no way
	 * to know the resulting stack.
	 * 
	 * @param <N> the stack where the given label is referenced
	 * @param em the emitter for otherwise-unreachable code
	 * @param lbl the label to place
	 * @return the emitter, as reachable via the given label
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public static <N extends Next> Emitter<N> placeDead(Emitter<Dead> em, Lbl<N> lbl) {
		em.mv.visitLabel(lbl.label);
		return (Emitter) em;
	}
}
