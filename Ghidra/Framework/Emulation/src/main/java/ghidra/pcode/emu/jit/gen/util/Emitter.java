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
import java.lang.classfile.ClassBuilder;
import java.lang.classfile.CodeBuilder;
import java.util.ArrayList;
import java.util.function.BiFunction;
import java.util.function.Function;

import ghidra.pcode.emu.jit.gen.util.Methods.*;
import ghidra.pcode.emu.jit.gen.util.Types.*;

/**
 * The central object for emitting type checked JVM bytecode.
 * <p>
 * This is either genius or a sign of some deep pathology. On one hand it allows the type-safe
 * generation of bytecode in Java classfiles. On the other, it requires an often onerous type
 * signature on any method of appreciable sophistication that uses it. The justification for this
 * utility library stems from our difficulties with error reporting in bytecode generation
 * libraries.
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
 * <p>
 * However, that requires more syntactic kruft, not to mention the manual bookkeeping to ensure we
 * use the previous <code>em<em>n</em></code> at each step. To work around this, we define instance
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
 * different forms, e.g., {@link Op#ldc__i}, but as a matter of opinion, having to specify the
 * intended form here is a benefit. The meat of this class is just the specification of the many
 * arities of {@link #emit}. It also includes some utilities for declaring local variables, and the
 * entry points for generating and defining methods.
 * <p>
 * To give an overall taste of using this utility library, here is an example for dynamically
 * generating a class that implements an interface. Note that the interface is <em>not</em>
 * dynamically generated. This is a common pattern as it allows the generated method to be invoked
 * without reflection.
 * 
 * {@snippet class = ghidra.pcode.emu.jit.gen.util.MyMethodExample region = MyIf}
 * 
 * {@snippet class = ghidra.pcode.emu.jit.gen.util.MyMethodExample region = gen}
 * 
 * @param <N> the contents of the stack after having emitted all the previous bytecodes
 */
public class Emitter<N> {
	static final Logger LOGGER = System.getLogger("Emitter");

	/** The wrapped Class-File API code builder */
	final CodeBuilder cb;
	/** The root scope of local declarations */
	final Scope rootScope;

	/**
	 * Create a new emitter by wrapping the given code builder.
	 * <p>
	 * Direct use of this constructor is not recommended, but is useful during transition from
	 * unchecked to checked bytecode generation.
	 *
	 * @param cb the Class-File API code builder
	 */
	public Emitter(CodeBuilder cb) {
		this.cb = cb;
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
	 * A 8-argument function
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
	 * (Not recommended) Wrap the given code builder with assumed stack contents
	 * <p>
	 * Use {@link #instanceWithBody} or {@link #staticWithBody} instead.
	 *
	 * @param <N> the stack contents
	 * @param cb the code builder
	 * @param assumedStack the assumed stack contents
	 * @return the emitter
	 */
	static <N extends Next> Emitter<N> assume(CodeBuilder cb, N assumedStack) {
		return new Emitter<>(cb);
	}

	/**
	 * Wrap the given code builder assuming an empty stack
	 * <p>
	 * Use {@link #instanceWithBody} or {@link #staticWithBody} instead.
	 *
	 * @param cb the code builder
	 * @return the emitter
	 */
	static Emitter<Bot> start(CodeBuilder cb) {
		return assume(cb, Next.BOTTOM);
	}

	/**
	 * Define a static method
	 * 
	 * @param clb The builder for the class to which this method definition is added.
	 * @param name the name of the method
	 * @param desc the method descriptor (signature)
	 * @param flags the flags (e.g., access modifiers)
	 * @param handler a lambda method to handle specification and code generation
	 */
	public static <MR extends BType, N extends Next> void staticWithBody(ClassBuilder clb,
			String name, MthDesc<MR, N> desc, int flags,
			Function<StaticMethodBuilder<MR, N>, Emitter<Dead>> handler) {
		clb.withMethodBody(name, desc.desc(), flags, cb -> {
			var dead = handler.apply(new StaticMethodBuilder<>(cb, name, desc, flags));
			Misc.finish(dead);
		});
	}

	static <MR extends BType, N extends Next> Def<MR, N> startStatic(CodeBuilder cb,
			MthDesc<MR, N> desc) {
		return new Def<>(start(cb), new ArrayList<>());
	}

	/**
	 * Define an instance method
	 * 
	 * @param clb the builder for the class to which this method definition is added.
	 * @param owner the owning type (must be same as that for the builder)
	 * @param name the name of the method
	 * @param desc the method descriptor (signature)
	 * @param flags the flags (e.g., access modifiers)
	 * @param handler a lambda method to handle specification and code generation
	 */
	public static <OT, MR extends BType, N extends Next> void instanceWithBody(ClassBuilder clb,
			TRef<OT> owner, String name, MthDesc<MR, N> desc, int flags,
			Function<InstanceMethodBuilder<OT, MR, N>, Emitter<Dead>> handler) {
		clb.withMethodBody(name, desc.desc(), flags, cb -> {
			var dead = handler.apply(new InstanceMethodBuilder<>(cb, owner, name, desc, flags));
			Misc.finish(dead);
		});
	}

	static <MR extends BType, OT, N extends Next> ObjDef<MR, OT, N> startInstance(
			TRef<OT> owner, CodeBuilder cb, MthDesc<MR, N> desc) {
		return new ObjDef<>(start(cb), new ArrayList<>());
	}
}
