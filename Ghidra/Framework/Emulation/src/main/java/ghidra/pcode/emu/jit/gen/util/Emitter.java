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

import java.lang.System.Logger;
import java.util.ArrayList;
import java.util.function.BiFunction;
import java.util.function.Function;

import org.objectweb.asm.*;

import ghidra.pcode.emu.jit.gen.util.Methods.*;
import ghidra.pcode.emu.jit.gen.util.Types.*;

/**
 * The central object for emitting type checked JVM bytecode.
 * <p>
 * This is either genius or a sign of some deep pathology. On one hand it allows the type-safe
 * generation of bytecode in Java classfiles. On the other, it requires an often onerous type
 * signature on any method of appreciable sophistication that uses it. The justification for this
 * utility library stems from our difficulties with error reporting in the ASM library. We certainly
 * appreciate the effort that has gone into that library, and must recognize its success in that it
 * has been used by the OpenJDK itself and eventually prompted them to devise an official classfile
 * API. Nevertheless, its analyses (e.g., max-stack computation) fail with inscrutable messages.
 * Admittedly, this only happens when we have generated invalid bytecode. For example, popping too
 * many items off the stack usually results in an {@link ArrayIndexOutOfBoundsException} instead of,
 * "Hey, you can't pop that here: [offset]". Similarly, if you push a long and then pop an int, you
 * typically get a {@link NullPointerException}. Unfortunately, these errors do not occur with the
 * offending {@code visitXInstruction()} call on the stack, but instead during
 * {@link MethodVisitor#visitMaxs(int, int)}, and so we could not easily debug and identify the
 * cause. We did find some ways to place breakpoints and at least derive the bytecode offset. We
 * then used additional dumps and instrumentation to map that back to our source that generated the
 * offending instruction. This has been an extremely onerous process. Additionally, when refactoring
 * bytecode generation, we are left with little if any assistance from the compiler or IDE. These
 * utilities seek to improve the situation.
 * <p>
 * Our goal is to devise a way leverage Java's Generics and its type checker to enforce stack
 * consistency of generated JVM bytecode. We want the Java compiler to reject code that tries, for
 * example, to emit an {@code iload} followed by an {@code lstore}, because there is clearly an
 * {@code int} on the stack where a {@code long} is required. We accomplish this by encoding the
 * stack contents (or at least the local knowledge of the stack contents) in this emitter's type
 * variable {@code <N>}. We encode the types of stack entries using a Lisp-style list. The bottom of
 * the stack is encoded as {@link Bot}. A list is encoded with {@link Ent} where the first type
 * parameter is the tail of the list (for things further down the stack), and the second type
 * parameter encodes the JVM machine type, e.g., {@link TInt}, of the element at that position. The
 * head of this list, i.e., the type {@code <N>}, is the top of the stack.
 * <p>
 * The resulting syntax for emitting code is a bit strange, but still quite effective in practice. A
 * problem we encounter in Java (and most OOP languages to our knowledge) is that an instance method
 * can always be invoked on a variable, no matter the variable's type parameters. Sure, we can
 * always throw an exception at runtime, but we want the compiler to reject it, which implies static
 * checking. Thus, while instance methods can be used for pure pushes, we cannot use them to
 * validate stack contents, e.g., for pops. Suppose we'd like to specify the {@code lcmp} bytecode
 * op. This would require a {@link TLong long} at the top of the stack, but there's no way we can
 * restrict {@code <N>} on the implied {@code this} parameter. Nor is there an obvious way to unpack
 * the contents of {@code <N>} so that we can remove the {@link TLong} and add a {@link TInt}.
 * Instead, we must turn to static methods.
 * <p>
 * This presents a different problem. We'd like to provide a syntax where the ops appear in the
 * order they are emitted. Usually, we'd chain instance methods, like such:
 * 
 * <pre>
 * em
 * 		.ldc(1)
 * 		.pop();
 * </pre>
 * <p>
 * However, we've already ruled out instance methods. Were we to use static methods, we'd get
 * something like:
 * 
 * <pre>
 * Op.pop(Op.ldc(em, 1));
 * </pre>
 * 
 * <p>
 * However, that fails to display the ops in order. We could instead use:
 * 
 * <pre>
 * var em1 = Op.ldc(em, 1);
 * var em2 = Op.pop(em1);
 * </pre>
 * 
 * However, that requires more syntactic kruft, not to mention the manual bookkeeping to ensure we
 * use the previous {@code em}<em>n</em> at each step. To work around this, we define instance
 * methods, e.g., {@link #emit(Function)}, that can accept references to static methods we provide,
 * each representing a JVM bytecode instruction. This allows those static methods to impose a
 * required structure on the stack. The static method can then return an emitter with a type
 * encoding the new stack contents. (See the {@link Op} class for examples.) Thus, we have a syntax
 * like:
 * 
 * <pre>
 * em
 * 		.emit(Op::ldc__i, 1)
 * 		.emit(Op::pop);
 * </pre>
 * <p>
 * While not ideal, it is succinct, allows method chaining, and displays the ops in order of
 * emission. (Note that we use this pattern even for pure pushes, where restricting {@code <N>} is
 * not necessary, just for syntactic consistency.) There are some rubs for operators that have
 * different forms, e.g., {@link Op#ldc__i(Emitter, int)}, but as a matter of opinion, having to
 * specify the intended form here is a benefit. The meat of this class is just the specification of
 * the many arities of {@code emit}. It also includes some utilities for declaring local variables,
 * and the entry points for generating and defining methods.
 * <p>
 * To give an overall taste of using this utility library, here is an example for dynamically
 * generating a class that implements an interface. Note that the interface is <em>not</em>
 * dynamically generated. This is a common pattern as it allows the generated method to be invoked
 * without reflection.
 * 
 * <pre>
 * interface MyIf {
 * 	int myMethod(int a, String b);
 * }
 * 
 * &lt;THIS extends MyIf&gt; void doGenerate(ClassVisitor cv) {
 * 	var mdescMyMethod = MthDesc.derive(MyIf::myMethod)
 * 			.check(MthDesc::returns, Types.T_INT)
 * 			.check(MthDesc::param, Types.T_INT)
 * 			.check(MthDesc::param, Types.refOf(String.class))
 * 			.check(MthDesc::build);
 * 	TRef&lt;THIS&gt; typeThis = Types.refExtends(MyIf.class, "Lmy.pkg.ImplMyIf;");
 * 	var paramsMyMethod = new Object() {
 * 		Local&lt;TRef&lt;THIS&gt;&gt; this_;
 * 		Local&lt;TInt&gt; a;
 * 		Local&lt;TRef&lt;String&gt;&gt; b;
 * 	};
 * 	var retMyMethod = Emitter.start(typeThis, cv, ACC_PUBLIC, "myMethod", mdescMyMethod)
 * 			.param(Def::param, Types.refOf(String.class), l -> paramsMyMethod.b = l)
 * 			.param(Def::param, Types.T_INT, l -> paramsMyMethod.a = l)
 * 			.param(Def::done, typeThis, l -> paramsMyMethod.this_ = l);
 * 	retMyMethod.em()
 * 			.emit(Op::iload, paramsMyMethod.a)
 * 			.emit(Op::ldc__i, 10)
 * 			.emit(Op::imul)
 * 			.emit(Op::ireturn, retMyMethod.ret())
 * 			.emit(Misc::finish);
 * }
 * </pre>
 * <p>
 * Yes, there is a bit of repetition; however, this accomplishes all our goals and a little more.
 * Note that the generated bytecode is essentially type checked all the way through to the method
 * definition in the {@code MyIf} interface. Here is the key: <em>We were to change the {@code MyIf}
 * interface, the compiler (and our IDE) would point out the inconsistency.</em> The first such
 * errors would be on {@code mdescMyMethod}. So, we would adjust it to match the new definition. The
 * compiler would then point out issues at {@code retMyMethod} -- assuming the parameters to
 * {@code myMethod} changed, and not just the return type. We would adjust it, along with the
 * contents of {@code paramsMyMethod} to accept the new parameter handles. If the return type of
 * {@code myMethod} changed, then the inferred type of {@code retMyMethod} will change accordingly.
 * <p>
 * Now for the generated bytecode. The {@link Op#iload(Emitter, Local)} requires the given variable
 * handle to have type {@link TInt}, and so if the parameter "{@code a}" changed type, the compiler
 * will point out that the opcode must also change. Similarly, the {@link Op#imul(Emitter)} requires
 * two ints and pushes an int result, so any resulting inconsistency will be caught. Finally, when
 * calling {@link Op#ireturn(Emitter, RetReq)}, two things are checked: 1) there is indeed an int on
 * the stack, and 2) the return type of the method, witnessed by {@code retMyMethod.ret()}, is also
 * an int. There are some occasional wrinkles, but for the most part, once we resolve all the
 * compilation errors, we are assured of type consistency in the generated code, both internally and
 * in its interface to other compiled code.
 * 
 * @param <N> the contents of the stack after having emitted all the previous bytecodes
 */
public class Emitter<N> {
	static final Logger LOGGER = System.getLogger("Emitter");

	/** The wrapped ASM method visitor */
	final MethodVisitor mv;
	/** The root scope of local declarations */
	final Scope rootScope;

	/**
	 * Create a new emitter by wrapping the given method visitor.
	 * <p>
	 * Direct use of this constructor is not recommended, but is useful during transition from
	 * unchecked to checked bytecode generation.
	 * 
	 * @param mv the ASM method visitor
	 */
	public Emitter(MethodVisitor mv) {
		this.mv = mv;
		rootScope = new RootScope<>(this, 0);
	}

	/**
	 * Stack contents
	 * 
	 * <p>
	 * There is really only one instance of {@link Next} and that is {@link SingletonEnt#INSTANCE}.
	 * We just cast it to the various types. Otherwise, these interfaces just exist as a means of
	 * leveraging Java's type checker.
	 */
	public interface Next {
		/**
		 * The bottom of the stack
		 */
		Bot BOTTOM = SingletonEnt.INSTANCE;
	}

	/**
	 * An entry on the stack
	 * 
	 * @param <N> the tail (portions below) of the stack
	 * @param <T> the top entry of this stack (or portion)
	 */
	public interface Ent<N extends Next, T extends BNonVoid> extends Next {
	}

	/**
	 * The bottom of the stack, i.e., the empty stack
	 */
	public interface Bot extends Next {
	}

	/**
	 * Use in place of stack contents when code emitted at this point would be unreachable
	 * <p>
	 * Note that this does not extend {@link Next}, which is why {@link Emitter} does not require
	 * {@code N} to extend {@link Next}. This interface also has no implementation.
	 */
	public interface Dead {
	}

	/**
	 * Defines the singleton instance of {@link Next}
	 * 
	 * @param <N> the tail
	 * @param <T> the top entry
	 */
	private record SingletonEnt<N extends Next, T extends BNonVoid>() implements Ent<N, T>, Bot {
		private static final SingletonEnt<?, ?> INSTANCE = new SingletonEnt<>();
	}

	/**
	 * Get the root scope for declaring local variables
	 * 
	 * @return the root scope
	 */
	public Scope rootScope() {
		return rootScope;
	}

	/**
	 * Emit a 0-argument operator
	 * <p>
	 * This can also be used to invoke generator subroutines whose only argument is the emitter.
	 * 
	 * @param <R> the return type
	 * @param func the method reference, e.g., {@link Op#pop(Emitter)}.
	 * @return the value returned by {@code func}
	 */
	public <R> R emit(Function<? super Emitter<N>, R> func) {
		return func.apply(this);
	}

	/**
	 * Emit a 1-argument operator
	 * <p>
	 * This can also be used to invoke generator subroutines.
	 * 
	 * @param <R> the return type
	 * @param func the method reference, e.g., {@link Op#ldc__i(Emitter, int)}.
	 * @param arg1 the argument (other than the emitter) to pass to {@code func}
	 * @return the value returned by {@code func}
	 */
	public <R, A1> R emit(BiFunction<? super Emitter<N>, A1, R> func, A1 arg1) {
		return func.apply(this, arg1);
	}

	/**
	 * A 3-argument function
	 * 
	 * @param <A0> the first argument type
	 * @param <A1> the next argument type
	 * @param <A2> the next argument type
	 * @param <R> the return type
	 */
	public interface A3Function<A0, A1, A2, R> {
		/**
		 * Invoke the function
		 * 
		 * @param arg0 the first argument
		 * @param arg1 the next argument
		 * @param arg2 the next argument
		 * @return the result
		 */
		R apply(A0 arg0, A1 arg1, A2 arg2);
	}

	/**
	 * A 3-argument consumer
	 * 
	 * @param <A0> the first argument type
	 * @param <A1> the next argument type
	 * @param <A2> the next argument type
	 */
	public interface A3Consumer<A0, A1, A2> {
		/**
		 * Invoke the consumer
		 * 
		 * @param arg0 the first argument
		 * @param arg1 the next argument
		 * @param arg2 the next argument
		 */
		void accept(A0 arg0, A1 arg1, A2 arg2);
	}

	/**
	 * Emit a 2-argument operator
	 * <p>
	 * This can also be used to invoke generator subroutines.
	 * 
	 * @param <R> the return type
	 * @param func the method reference
	 * @param arg1 an argument (other than the emitter) to pass to {@code func}
	 * @param arg2 the next argument
	 * @return the value returned by {@code func}
	 */
	public <R, A1, A2> R emit(A3Function<? super Emitter<N>, A1, A2, R> func, A1 arg1, A2 arg2) {
		return func.apply(this, arg1, arg2);
	}

	/**
	 * A 4-argument function
	 * 
	 * @param <A0> the first argument type
	 * @param <A1> the next argument type
	 * @param <A2> the next argument type
	 * @param <A3> the next argument type
	 * @param <R> the return type
	 */
	public interface A4Function<A0, A1, A2, A3, R> {
		/**
		 * Invoke the function
		 * 
		 * @param arg0 the first argument
		 * @param arg1 the next argument
		 * @param arg2 the next argument
		 * @param arg3 the next argument
		 * @return the result
		 */
		R apply(A0 arg0, A1 arg1, A2 arg2, A3 arg3);
	}

	/**
	 * A 4-argument consumer
	 * 
	 * @param <A0> the first argument type
	 * @param <A1> the next argument type
	 * @param <A2> the next argument type
	 * @param <A3> the next argument type
	 */
	public interface A4Consumer<A0, A1, A2, A3> {
		/**
		 * Invoke the consumer
		 * 
		 * @param arg0 the first argument
		 * @param arg1 the next argument
		 * @param arg2 the next argument
		 * @param arg3 the next argument
		 */
		void accept(A0 arg0, A1 arg1, A2 arg2, A3 arg3);
	}

	/**
	 * Emit a 3-argument operator
	 * <p>
	 * This can also be used to invoke generator subroutines.
	 * 
	 * @param <R> the return type
	 * @param func the method reference
	 * @param arg1 an argument (other than the emitter) to pass to {@code func}
	 * @param arg2 the next argument
	 * @param arg3 the next argument
	 * @return the value returned by {@code func}
	 */
	public <R, A1, A2, A3> R emit(A4Function<Emitter<N>, A1, A2, A3, R> func, A1 arg1, A2 arg2,
			A3 arg3) {
		return func.apply(this, arg1, arg2, arg3);
	}

	/**
	 * A 5-argument function
	 * 
	 * @param <A0> the first argument type
	 * @param <A1> the next argument type
	 * @param <A2> the next argument type
	 * @param <A3> the next argument type
	 * @param <A4> the next argument type
	 * @param <R> the return type
	 */
	public interface A5Function<A0, A1, A2, A3, A4, R> {
		/**
		 * Invoke the function
		 * 
		 * @param arg0 the first argument
		 * @param arg1 the next argument
		 * @param arg2 the next argument
		 * @param arg3 the next argument
		 * @param arg4 the next argument
		 * @return the result
		 */
		R apply(A0 arg0, A1 arg1, A2 arg2, A3 arg3, A4 arg4);
	}

	/**
	 * Emit a 4-argument operator
	 * <p>
	 * This can also be used to invoke generator subroutines.
	 * 
	 * @param <R> the return type
	 * @param func the method reference
	 * @param arg1 an argument (other than the emitter) to pass to {@code func}
	 * @param arg2 the next argument
	 * @param arg3 the next argument
	 * @param arg4 the next argument
	 * @return the value returned by {@code func}
	 */
	public <R, A1, A2, A3, A4> R emit(A5Function<? super Emitter<N>, A1, A2, A3, A4, R> func,
			A1 arg1, A2 arg2, A3 arg3, A4 arg4) {
		return func.apply(this, arg1, arg2, arg3, arg4);
	}

	/**
	 * A 6-argument function
	 * 
	 * @param <A0> the first argument type
	 * @param <A1> the next argument type
	 * @param <A2> the next argument type
	 * @param <A3> the next argument type
	 * @param <A4> the next argument type
	 * @param <A5> the next argument type
	 * @param <R> the return type
	 */
	public interface A6Function<A0, A1, A2, A3, A4, A5, R> {
		/**
		 * Invoke the function
		 * 
		 * @param arg0 the first argument
		 * @param arg1 the next argument
		 * @param arg2 the next argument
		 * @param arg3 the next argument
		 * @param arg4 the next argument
		 * @param arg5 the next argument
		 * @return the result
		 */
		R apply(A0 arg0, A1 arg1, A2 arg2, A3 arg3, A4 arg4, A5 arg5);
	}

	/**
	 * Emit a 5-argument operator
	 * <p>
	 * This can also be used to invoke generator subroutines.
	 * 
	 * @param <R> the return type
	 * @param func the method reference
	 * @param arg1 an argument (other than the emitter) to pass to {@code func}
	 * @param arg2 the next argument
	 * @param arg3 the next argument
	 * @param arg4 the next argument
	 * @param arg5 the next argument
	 * @return the value returned by {@code func}
	 */
	public <R, A1, A2, A3, A4, A5> R emit(
			A6Function<? super Emitter<N>, A1, A2, A3, A4, A5, R> func, A1 arg1, A2 arg2,
			A3 arg3, A4 arg4, A5 arg5) {
		return func.apply(this, arg1, arg2, arg3, arg4, arg5);
	}

	/**
	 * A 7-argument function
	 * 
	 * @param <A0> the first argument type
	 * @param <A1> the next argument type
	 * @param <A2> the next argument type
	 * @param <A3> the next argument type
	 * @param <A4> the next argument type
	 * @param <A5> the next argument type
	 * @param <A6> the next argument type
	 * @param <R> the return type
	 */
	public interface A7Function<A0, A1, A2, A3, A4, A5, A6, R> {
		/**
		 * Invoke the function
		 * 
		 * @param arg0 the first argument
		 * @param arg1 the next argument
		 * @param arg2 the next argument
		 * @param arg3 the next argument
		 * @param arg4 the next argument
		 * @param arg5 the next argument
		 * @param arg6 the next argument
		 * @return the result
		 */
		R apply(A0 arg0, A1 arg1, A2 arg2, A3 arg3, A4 arg4, A5 arg5, A6 arg6);
	}

	/**
	 * Emit a 6-argument operator
	 * <p>
	 * This can also be used to invoke generator subroutines.
	 * 
	 * @param <R> the return type
	 * @param func the method reference
	 * @param arg1 an argument (other than the emitter) to pass to {@code func}
	 * @param arg2 the next argument
	 * @param arg3 the next argument
	 * @param arg4 the next argument
	 * @param arg5 the next argument
	 * @param arg6 the next argument
	 * @return the value returned by {@code func}
	 */
	public <R, A1, A2, A3, A4, A5, A6> R emit(
			A7Function<? super Emitter<N>, A1, A2, A3, A4, A5, A6, R> func, A1 arg1,
			A2 arg2, A3 arg3, A4 arg4, A5 arg5, A6 arg6) {
		return func.apply(this, arg1, arg2, arg3, arg4, arg5, arg6);
	}

	/**
	 * A 7-argument function
	 * 
	 * @param <A0> the first argument type
	 * @param <A1> the next argument type
	 * @param <A2> the next argument type
	 * @param <A3> the next argument type
	 * @param <A4> the next argument type
	 * @param <A5> the next argument type
	 * @param <A6> the next argument type
	 * @param <A7> the next argument type
	 * @param <R> the return type
	 */
	public interface A8Function<A0, A1, A2, A3, A4, A5, A6, A7, R> {
		/**
		 * Invoke the function
		 * 
		 * @param arg0 the first argument
		 * @param arg1 the next argument
		 * @param arg2 the next argument
		 * @param arg3 the next argument
		 * @param arg4 the next argument
		 * @param arg5 the next argument
		 * @param arg6 the next argument
		 * @param arg7 the next argument
		 * @return the result
		 */
		R apply(A0 arg0, A1 arg1, A2 arg2, A3 arg3, A4 arg4, A5 arg5, A6 arg6, A7 arg7);
	}

	/**
	 * Emit a 7-argument operator
	 * <p>
	 * This can also be used to invoke generator subroutines.
	 * 
	 * @param <R> the return type
	 * @param func the method reference
	 * @param arg1 an argument (other than the emitter) to pass to {@code func}
	 * @param arg2 the next argument
	 * @param arg3 the next argument
	 * @param arg4 the next argument
	 * @param arg5 the next argument
	 * @param arg6 the next argument
	 * @param arg7 the next argument
	 * @return the value returned by {@code func}
	 */
	public <R, A1, A2, A3, A4, A5, A6, A7> R emit(
			A8Function<? super Emitter<N>, A1, A2, A3, A4, A5, A6, A7, R> func, A1 arg1, A2 arg2,
			A3 arg3, A4 arg4, A5 arg5, A6 arg6, A7 arg7) {
		return func.apply(this, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
	}

	/**
	 * (Not recommended) Wrap the given method visitor with assumed stack contents
	 * <p>
	 * {@link #start(ClassVisitor, int, String, MthDesc)} or
	 * {@link #start(TRef, ClassVisitor, int, String, MthDesc)} is recommended instead.
	 * 
	 * @param <N> the stack contents
	 * @param mv the ASM method visitor
	 * @param assumedStack the assumed stack contents
	 * @return the emitter
	 */
	public static <N extends Next> Emitter<N> assume(MethodVisitor mv, N assumedStack) {
		return new Emitter<>(mv);
	}

	/**
	 * Wrap the given method visitor assuming an empty stack
	 * <p>
	 * {@link #start(ClassVisitor, int, String, MthDesc)} or
	 * {@link #start(TRef, ClassVisitor, int, String, MthDesc)} is recommended instead.
	 * 
	 * @param mv the ASM method visitor
	 * @return the emitter
	 */
	public static Emitter<Bot> start(MethodVisitor mv) {
		mv.visitCode();
		return assume(mv, Next.BOTTOM);
	}

	/**
	 * Define a static method
	 * 
	 * @param <MR> the type returned by the method
	 * @param <N> the parameter types of the method
	 * @param cv the ASM class visitor
	 * @param access the access flags (static is added automatically)
	 * @param name the name of the method
	 * @param desc the method descriptor
	 * @return an object to aid further definition of the method
	 */
	public static <MR extends BType, N extends Next> Def<MR, N> start(ClassVisitor cv, int access,
			String name, MthDesc<MR, N> desc) {
		access |= Opcodes.ACC_STATIC;
		MethodVisitor mv = cv.visitMethod(access, name, desc.desc(), null, null);
		return new Def<>(start(mv), new ArrayList<>());
	}

	/**
	 * Define an instance method
	 * 
	 * @param <MR> the type returned by the method
	 * @param <OT> the type owning the method
	 * @param <N> the parameter types of the method
	 * @param owner the owner type (as a reference type)
	 * @param cv the ASM class visitor
	 * @param access the access flags (static is forcibly removed)
	 * @param name the name of the method
	 * @param desc the method descriptor
	 * @return an object to aid further definition of the method
	 */
	public static <MR extends BType, OT, N extends Next> ObjDef<MR, OT, N> start(TRef<OT> owner,
			ClassVisitor cv, int access, String name, MthDesc<MR, N> desc) {
		access &= ~Opcodes.ACC_STATIC;
		MethodVisitor mv = cv.visitMethod(access, name, desc.desc(), null, null);
		return new ObjDef<>(start(mv), new ArrayList<>());
	}
}
