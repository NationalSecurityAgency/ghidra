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

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.function.*;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Type;

import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Methods.Def.ParamFunction;
import ghidra.pcode.emu.jit.gen.util.Methods.Def.ThisFunction;
import ghidra.pcode.emu.jit.gen.util.Types.*;

/**
 * Utilities for invoking, declaring, and defining methods
 * <p>
 * Method invocation requires a bit more kruft than we would like, it that kruft does have its
 * benefits. (For an example of method definition, see {@link Emitter}.)
 * <p>
 * Consider the example where we'd like to invoke {@link Integer#compare(int, int)}:
 * 
 * <pre>
 * var mdescIntegerCompare = MthDesc.derive(Integer::compare)
 * 		.check(MthDesc::returns, Types.T_INT)
 * 		.check(MthDesc::param, Types.T_INT)
 * 		.check(MthDesc::param, Types.T_INT)
 * 		.check(MthDesc::build);
 * em
 * 		.emit(Op::iload, params.a)
 * 		.emit(Op::ldc__i, 20)
 * 		.emit(Op::invokestatic, Types.refOf(Integer.class), "compare", mdescIntegerCompare,
 * 			false)
 * 		.step(Inv::takeArg)
 * 		.step(Inv::takeArg)
 * 		.step(Inv::ret)
 * 		.emit(Op::ireturn, retReq);
 * </pre>
 * <p>
 * The first requirement (as in the case of defining a method) is to obtain the descriptor of the
 * target method. There are a few ways to generate method descriptors, but the safest when calling a
 * compiled or library method is to derive it from a reference to that method. There is no such
 * thing as a "method literal" in Java, but there are method references, and we can match the types
 * of those references. One wrinkle to this, however, is that we cannot distinguish auto-boxed
 * parameters from those that genuinely accept the boxed type, i.e., both {@code void f(int a)} and
 * {@code void g(Integer b)} can be made into references of type {@link Consumer}{@code <Integer>},
 * because {@code <int>} is not a legal type signature. Thus, we require the user to call
 * {@link MthDescCheckedBuilderP#check(BiFunction, Object)} with, e.g.,
 * {@link MthDesc#param(MthDescCheckedBuilderP, TInt)} to specify that an {@link Integer} is
 * actually an {@code int}. However, we cannot check that the user did this correctly until runtime.
 * Still, we are able to prevent a {@code Hippo} parameter from receiving an {@code int}, and that
 * is much better than nothing.
 * <p>
 * Once we have the method descriptor, we can use it in invocation operators, e.g.,
 * {@link Op#invokestatic(Emitter, TRef, String, MthDesc, boolean)}. In an of itself, this operator
 * does <em>not</em> consume nor push anything to the stack. Instead, it returns an {@link Inv}
 * object, which facilitates the popping and checking of each parameter, followed by the pushing of
 * the returned value, if non-void. It is not obvious to us (if such a technique even exists) to pop
 * an arbitrary number of entries from {@code <N>} in a single method. Instead, we have to treat
 * Java's type checker as a sort of automaton that we can step, one pop at a time, by invoking a
 * method. This method is {@link Inv#takeArg(Inv)}, which for chaining purposes, is most easily
 * invoked using the aptly-named {@link Inv#step(Function)} instance method. We would rather not
 * have to do it this way, as it is unnecessary kruft that may also have a run-time cost. One
 * benefit, however, is that if the arguments on the stack do not match the parameters required by
 * the descriptor, the first mismatched {@code takeArg} line (corresponding to the right-most
 * mismatched parameter) will fail to compile, and so we know <em>which</em> argument is incorrect.
 * Finally, we must do one last step to to push the return value, e.g., {@link Inv#ret(Inv)}. This
 * will check that all parameters have been popped, and then push a value of the descriptor's return
 * type. It returns the resulting emitter. For a void method, use {@link Inv#retVoid(Inv)} to avert
 * the push. Unfortunately, {@code ret} is still permitted, but at least downstream operators are
 * likely to fail, since nothing should consume {@link TVoid}.
 */
public interface Methods {

	/**
	 * A method descriptor
	 * 
	 * @param <MR> the (machine) type returned by the method
	 * @param <N> the parameter types encoded as in {@link Emitter} where the top corresponds to the
	 *            right-most parameter.
	 * @param desc the descriptor as a string, as in
	 *            {@link MethodVisitor#visitMethodInsn(int, String, String, String, boolean)}.
	 */
	public record MthDesc<MR extends BType, N extends Next>(String desc) {

		/**
		 * Begin building a method descriptor that returns the given (machine) type
		 * 
		 * @param <MR> the return type
		 * @param retType the return type
		 * @return the builder
		 */
		public static <MR extends BType> MthDescBuilder<MR, Bot> returns(MR retType) {
			return new MthDescBuilder<>(retType.type());
		}

		/**
		 * Begin building a method descriptor that returns the given (source) type
		 * 
		 * @param retType the return type
		 * @return the builder
		 */
		public static MthDescBuilder<TInt, Bot> returns(SType retType) {
			return new MthDescBuilder<>(retType.type());
		}

		/**
		 * Obtain a method descriptor for a reflected method of unknown or unspecified type
		 * <p>
		 * All bets are off for static type checking, but this at least obtains the descriptor as a
		 * string at runtime.
		 * 
		 * @param method the method
		 * @return the untyped descriptor
		 */
		public static MthDesc<?, ?> reflect(Method method) {
			return new MthDesc<>(Type.getMethodDescriptor(method));
		}

		/**
		 * Begin building a method descriptor derived from the given method reference
		 * <p>
		 * NOTE: This is imperfect because method refs allow {@code ? super} for the return type and
		 * {@code ? extends} for each parameter. Furthermore, primitives must be boxed, and so we
		 * can't distinguish primitive parameters from their boxed types. Still, this is better than
		 * nothing. For an example of this, see {@link Methods} or {@link Emitter}.
		 * 
		 * @param <R> the return type, boxed
		 * @param <A0> the first argument type, boxed
		 * @param func the method reference
		 * @return the checked builder
		 */
		public static <R, A0> MthDescCheckedBuilderR<R, CkEnt<CkBot, A0>>
				derive(Function<A0, R> func) {
			return new MthDescCheckedBuilderR<>();
		}

		/**
		 * Begin building a method descriptor derived from the given method reference
		 * 
		 * @see #derive(Function)
		 * @param <R> the return type, boxed
		 * @param <A0> the first argument type, boxed
		 * @param <A1> another argument type, boxed
		 * @param func the method reference
		 * @return the checked builder
		 */
		public static <R, A0, A1> MthDescCheckedBuilderR<R, CkEnt<CkEnt<CkBot, A1>, A0>>
				derive(BiFunction<A0, A1, R> func) {
			return new MthDescCheckedBuilderR<>();
		}

		/**
		 * Begin building an instance method descriptor derived from the given method reference
		 * <p>
		 * This implicitly drops the object reference that is normally included in static references
		 * to instance methods.
		 * 
		 * @see #derive(Function)
		 * @param <R> the return type, boxed
		 * @param <A0> the object reference type, dropped
		 * @param <A1> another argument type, boxed
		 * @param func the method reference
		 * @return the checked builder
		 */
		public static <R, A0, A1> MthDescCheckedBuilderR<R, CkEnt<CkBot, A1>>
				deriveInst(BiFunction<A0, A1, R> func) {
			return new MthDescCheckedBuilderR<>();
		}

		/**
		 * Begin building a method descriptor derived from the given method reference
		 * 
		 * @see #derive(Function)
		 * @param <R> the return type, boxed
		 * @param <A0> the first argument type, boxed
		 * @param <A1> another argument type, boxed
		 * @param <A2> another argument type, boxed
		 * @param func the method reference
		 * @return the checked builder
		 */
		public static <R, A0, A1, A2>
				MthDescCheckedBuilderR<R, CkEnt<CkEnt<CkEnt<CkBot, A2>, A1>, A0>>
				derive(A3Function<A0, A1, A2, R> func) {
			return new MthDescCheckedBuilderR<>();
		}

		/**
		 * Begin building a method descriptor derived from the given method reference
		 * 
		 * @see #derive(Function)
		 * @param <A0> the first argument type, boxed
		 * @param <A1> another argument type, boxed
		 * @param <A2> another argument type, boxed
		 * @param func the method reference
		 * @return the checked builder
		 */
		public static <A0, A1, A2>
				MthDescCheckedBuilderR<Void, CkEnt<CkEnt<CkEnt<CkBot, A2>, A1>, A0>>
				derive(A3Consumer<A0, A1, A2> func) {
			return new MthDescCheckedBuilderR<>();
		}

		/**
		 * Begin building a method descriptor derived from the given method reference
		 * 
		 * @see #derive(Function)
		 * @param <A0> the object type, dropped
		 * @param <A1> another argument type, boxed
		 * @param <A2> another argument type, boxed
		 * @param func the method reference
		 * @return the checked builder
		 */
		public static <A0, A1, A2> MthDescCheckedBuilderR<Void, CkEnt<CkEnt<CkBot, A2>, A1>>
				deriveInst(A3Consumer<A0, A1, A2> func) {
			return new MthDescCheckedBuilderR<>();
		}

		/**
		 * Begin building a method descriptor derived from the given method reference
		 * 
		 * @see #derive(Function)
		 * @param <R> the return type, boxed
		 * @param <A0> the first argument type, boxed
		 * @param <A1> another argument type, boxed
		 * @param <A2> another argument type, boxed
		 * @param <A3> another argument type, boxed
		 * @param func the method reference
		 * @return the checked builder
		 */
		public static <R, A0, A1, A2, A3>
				MthDescCheckedBuilderR<R, CkEnt<CkEnt<CkEnt<CkEnt<CkBot, A3>, A2>, A1>, A0>>
				derive(A4Function<A0, A1, A2, A3, R> func) {
			return new MthDescCheckedBuilderR<>();
		}

		/**
		 * Begin building a method descriptor derived from the given method reference
		 * 
		 * @see #derive(Function)
		 * @param <A0> the first argument type, boxed
		 * @param <A1> another argument type, boxed
		 * @param <A2> another argument type, boxed
		 * @param <A3> another argument type, boxed
		 * @param func the method reference
		 * @return the checked builder
		 */
		public static <A0, A1, A2, A3>
				MthDescCheckedBuilderR<Void, CkEnt<CkEnt<CkEnt<CkEnt<CkBot, A3>, A2>, A1>, A0>>
				derive(A4Consumer<A0, A1, A2, A3> func) {
			return new MthDescCheckedBuilderR<>();
		}

		/**
		 * Begin building an instance method descriptor derived from the given method reference
		 * 
		 * @see #derive(Function)
		 * @param <A0> the object reference
		 * @param <A1> another argument type, boxed
		 * @param <A2> another argument type, boxed
		 * @param <A3> another argument type, boxed
		 * @param func the method reference
		 * @return the checked builder
		 */
		public static <A0, A1, A2, A3>
				MthDescCheckedBuilderR<Void, CkEnt<CkEnt<CkEnt<CkBot, A3>, A2>, A1>>
				deriveInst(A4Consumer<A0, A1, A2, A3> func) {
			return new MthDescCheckedBuilderR<>();
		}

		/**
		 * Begin building a method descriptor derived from the given method reference
		 * 
		 * @see #derive(Function)
		 * @param <R> the return type, boxed
		 * @param <A0> the first argument type, boxed
		 * @param <A1> another argument type, boxed
		 * @param <A2> another argument type, boxed
		 * @param <A3> another argument type, boxed
		 * @param func the method reference
		 * @return the checked builder
		 */
		public static <R, A0, A1, A2, A3, A4>
				MthDescCheckedBuilderR<R,
					CkEnt<CkEnt<CkEnt<CkEnt<CkEnt<CkBot, A4>, A3>, A2>, A1>, A0>>
				derive(A5Function<A0, A1, A2, A3, A4, R> func) {
			return new MthDescCheckedBuilderR<>();
		}

		/**
		 * Begin building a method descriptor derived from the given method reference
		 * 
		 * @see #derive(Function)
		 * @param <R> the return type, boxed
		 * @param <A0> the first argument type, boxed
		 * @param <A1> another argument type, boxed
		 * @param <A2> another argument type, boxed
		 * @param <A3> another argument type, boxed
		 * @param func the method reference
		 * @return the checked builder
		 */
		public static <R, A0, A1, A2, A3, A4, A5,
			A6> MthDescCheckedBuilderR<R,
				CkEnt<CkEnt<CkEnt<CkEnt<CkEnt<CkEnt<CkEnt<CkBot, A6>, A5>, A4>, A3>, A2>, A1>, A0>>
				derive(A7Function<A0, A1, A2, A3, A4, A5, A6, R> func) {
			return new MthDescCheckedBuilderR<>();
		}

		/**
		 * Specify the return type of a checked builder
		 * <p>
		 * This may not be used for primitive types, but can be used if the method genuinely returns
		 * the boxed type.
		 * 
		 * @param <R> the (perhaps boxed) return type
		 * @param <CN> the boxed parameter types for later checking
		 * @param builder the (stage 1) builder
		 * @param retType the return type
		 * @return the (stage 2) builder
		 */
		public static <R, CN extends CkNext> MthDescCheckedBuilderP<TRef<R>, Bot, CN>
				returns(MthDescCheckedBuilderR<R, CN> builder, TRef<R> retType) {
			return new MthDescCheckedBuilderP<>(retType.type());
		}

		/**
		 * Specify a void return type for a checked builder
		 * 
		 * @param <CN> the boxed parameter types for later checking
		 * @param builder the (stage 1) builder
		 * @param retType the return type
		 * @return the (stage 2) builder
		 */
		public static <CN extends CkNext> MthDescCheckedBuilderP<TVoid, Bot, CN>
				returns(MthDescCheckedBuilderR<Void, CN> builder, TVoid retType) {
			return new MthDescCheckedBuilderP<>(retType.type());
		}

		/**
		 * Specify a boolean return type for a checked builder
		 * 
		 * @param <CN> the boxed parameter types for later checking
		 * @param builder the (stage 1) builder
		 * @param retType the return type
		 * @return the (stage 2) builder
		 */
		public static <CN extends CkNext> MthDescCheckedBuilderP<TInt, Bot, CN>
				returns(MthDescCheckedBuilderR<Boolean, CN> builder, TBool retType) {
			return new MthDescCheckedBuilderP<>(retType.type());
		}

		/**
		 * Specify a byte return type for a checked builder
		 * 
		 * @param <CN> the boxed parameter types for later checking
		 * @param builder the (stage 1) builder
		 * @param retType the return type
		 * @return the (stage 2) builder
		 */
		public static <CN extends CkNext> MthDescCheckedBuilderP<TInt, Bot, CN>
				returns(MthDescCheckedBuilderR<Boolean, CN> builder, TByte retType) {
			return new MthDescCheckedBuilderP<>(retType.type());
		}

		/**
		 * Specify a char return type for a checked builder
		 * 
		 * @param <CN> the boxed parameter types for later checking
		 * @param builder the (stage 1) builder
		 * @param retType the return type
		 * @return the (stage 2) builder
		 */
		public static <CN extends CkNext> MthDescCheckedBuilderP<TInt, Bot, CN>
				returns(MthDescCheckedBuilderR<Boolean, CN> builder, TChar retType) {
			return new MthDescCheckedBuilderP<>(retType.type());
		}

		/**
		 * Specify a short return type for a checked builder
		 * 
		 * @param <CN> the boxed parameter types for later checking
		 * @param builder the (stage 1) builder
		 * @param retType the return type
		 * @return the (stage 2) builder
		 */
		public static <CN extends CkNext> MthDescCheckedBuilderP<TInt, Bot, CN>
				returns(MthDescCheckedBuilderR<Boolean, CN> builder, TShort retType) {
			return new MthDescCheckedBuilderP<>(retType.type());
		}

		/**
		 * Specify an int return type for a checked builder
		 * 
		 * @param <CN> the boxed parameter types for later checking
		 * @param builder the (stage 1) builder
		 * @param retType the return type
		 * @return the (stage 2) builder
		 */
		public static <CN extends CkNext> MthDescCheckedBuilderP<TInt, Bot, CN>
				returns(MthDescCheckedBuilderR<Integer, CN> builder, TInt retType) {
			return new MthDescCheckedBuilderP<>(retType.type());
		}

		/**
		 * Specify a long return type for a checked builder
		 * 
		 * @param <CN> the boxed parameter types for later checking
		 * @param builder the (stage 1) builder
		 * @param retType the return type
		 * @return the (stage 2) builder
		 */
		public static <CN extends CkNext> MthDescCheckedBuilderP<TLong, Bot, CN>
				returns(MthDescCheckedBuilderR<Long, CN> builder, TLong retType) {
			return new MthDescCheckedBuilderP<>(retType.type());
		}

		/**
		 * Specify a float return type for a checked builder
		 * 
		 * @param <CN> the boxed parameter types for later checking
		 * @param builder the (stage 1) builder
		 * @param retType the return type
		 * @return the (stage 2) builder
		 */
		public static <CN extends CkNext> MthDescCheckedBuilderP<TFloat, Bot, CN>
				returns(MthDescCheckedBuilderR<Integer, CN> builder, TFloat retType) {
			return new MthDescCheckedBuilderP<>(retType.type());
		}

		/**
		 * Specify a double return type for a checked builder
		 * 
		 * @param <CN> the boxed parameter types for later checking
		 * @param builder the (stage 1) builder
		 * @param retType the return type
		 * @return the (stage 2) builder
		 */
		public static <CN extends CkNext> MthDescCheckedBuilderP<TDouble, Bot, CN>
				returns(MthDescCheckedBuilderR<Long, CN> builder, TDouble retType) {
			return new MthDescCheckedBuilderP<>(retType.type());
		}

		/**
		 * Specify a reference parameter type
		 * 
		 * @param <MR> the method return type
		 * @param <N> the actual parameter types specified so far
		 * @param <P> the parameter type
		 * @param <CN1> the boxed parameter types remaining
		 * @param <CN0> the boxed type for the parameter whose type is being specified
		 * @param builder the builder
		 * @param paramType the specified parameter type
		 * @return the builder
		 */
		@SuppressWarnings({ "rawtypes", "unchecked" })
		public static <MR extends BType, N extends Next, P, CN1 extends CkNext,
			CN0 extends CkEnt<CN1, P>> MthDescCheckedBuilderP<MR, Ent<N, TRef<P>>, CN1>
				param(MthDescCheckedBuilderP<MR, N, CN0> builder, TRef<P> paramType) {
			builder.paramTypes.add(paramType.type());
			return (MthDescCheckedBuilderP) builder;
		}

		/**
		 * Specify a boolean parameter type
		 * 
		 * @param <MR> the method return type
		 * @param <N> the actual parameter types specified so far
		 * @param <CN1> the boxed parameter types remaining
		 * @param <CN0> the boxed type for the parameter whose type is being specified
		 * @param builder the builder
		 * @param paramType the specified parameter type
		 * @return the builder
		 */
		@SuppressWarnings({ "rawtypes", "unchecked" })
		public static <MR extends BType, N extends Next, CN1 extends CkNext,
			CN0 extends CkEnt<CN1, Integer>> MthDescCheckedBuilderP<MR, Ent<N, TInt>, CN1>
				param(MthDescCheckedBuilderP<MR, N, CN0> builder, TBool paramType) {
			builder.paramTypes.add(paramType.type());
			return (MthDescCheckedBuilderP) builder;
		}

		/**
		 * Specify a byte parameter type
		 * 
		 * @param <MR> the method return type
		 * @param <N> the actual parameter types specified so far
		 * @param <CN1> the boxed parameter types remaining
		 * @param <CN0> the boxed type for the parameter whose type is being specified
		 * @param builder the builder
		 * @param paramType the specified parameter type
		 * @return the builder
		 */
		@SuppressWarnings({ "rawtypes", "unchecked" })
		public static <MR extends BType, N extends Next, CN1 extends CkNext,
			CN0 extends CkEnt<CN1, Integer>> MthDescCheckedBuilderP<MR, Ent<N, TInt>, CN1>
				param(MthDescCheckedBuilderP<MR, N, CN0> builder, TByte paramType) {
			builder.paramTypes.add(paramType.type());
			return (MthDescCheckedBuilderP) builder;
		}

		/**
		 * Specify a char parameter type
		 * 
		 * @param <MR> the method return type
		 * @param <N> the actual parameter types specified so far
		 * @param <CN1> the boxed parameter types remaining
		 * @param <CN0> the boxed type for the parameter whose type is being specified
		 * @param builder the builder
		 * @param paramType the specified parameter type
		 * @return the builder
		 */
		@SuppressWarnings({ "rawtypes", "unchecked" })
		public static <MR extends BType, N extends Next, CN1 extends CkNext,
			CN0 extends CkEnt<CN1, Integer>> MthDescCheckedBuilderP<MR, Ent<N, TInt>, CN1>
				param(MthDescCheckedBuilderP<MR, N, CN0> builder, TChar paramType) {
			builder.paramTypes.add(paramType.type());
			return (MthDescCheckedBuilderP) builder;
		}

		/**
		 * Specify a short parameter type
		 * 
		 * @param <MR> the method return type
		 * @param <N> the actual parameter types specified so far
		 * @param <CN1> the boxed parameter types remaining
		 * @param <CN0> the boxed type for the parameter whose type is being specified
		 * @param builder the builder
		 * @param paramType the specified parameter type
		 * @return the builder
		 */
		@SuppressWarnings({ "rawtypes", "unchecked" })
		public static <MR extends BType, N extends Next, CN1 extends CkNext,
			CN0 extends CkEnt<CN1, Integer>> MthDescCheckedBuilderP<MR, Ent<N, TInt>, CN1>
				param(MthDescCheckedBuilderP<MR, N, CN0> builder, TShort paramType) {
			builder.paramTypes.add(paramType.type());
			return (MthDescCheckedBuilderP) builder;
		}

		/**
		 * Specify an int parameter type
		 * 
		 * @param <MR> the method return type
		 * @param <N> the actual parameter types specified so far
		 * @param <CN1> the boxed parameter types remaining
		 * @param <CN0> the boxed type for the parameter whose type is being specified
		 * @param builder the builder
		 * @param paramType the specified parameter type
		 * @return the builder
		 */
		@SuppressWarnings({ "rawtypes", "unchecked" })
		public static <MR extends BType, N extends Next, CN1 extends CkNext,
			CN0 extends CkEnt<CN1, Integer>> MthDescCheckedBuilderP<MR, Ent<N, TInt>, CN1>
				param(MthDescCheckedBuilderP<MR, N, CN0> builder, TInt paramType) {
			builder.paramTypes.add(paramType.type());
			return (MthDescCheckedBuilderP) builder;
		}

		/**
		 * Specify a long parameter type
		 * 
		 * @param <MR> the method return type
		 * @param <N> the actual parameter types specified so far
		 * @param <CN1> the boxed parameter types remaining
		 * @param <CN0> the boxed type for the parameter whose type is being specified
		 * @param builder the builder
		 * @param paramType the specified parameter type
		 * @return the builder
		 */
		@SuppressWarnings({ "rawtypes", "unchecked" })
		public static <MR extends BType, N extends Next, CN1 extends CkNext,
			CN0 extends CkEnt<CN1, Long>> MthDescCheckedBuilderP<MR, Ent<N, TLong>, CN1>
				param(MthDescCheckedBuilderP<MR, N, CN0> builder, TLong paramType) {
			builder.paramTypes.add(paramType.type());
			return (MthDescCheckedBuilderP) builder;
		}

		/**
		 * Specify a float parameter type
		 * 
		 * @param <MR> the method return type
		 * @param <N> the actual parameter types specified so far
		 * @param <CN1> the boxed parameter types remaining
		 * @param <CN0> the boxed type for the parameter whose type is being specified
		 * @param builder the builder
		 * @param paramType the specified parameter type
		 * @return the builder
		 */
		@SuppressWarnings({ "rawtypes", "unchecked" })
		public static <MR extends BType, N extends Next, CN1 extends CkNext,
			CN0 extends CkEnt<CN1, Float>> MthDescCheckedBuilderP<MR, Ent<N, TFloat>, CN1>
				param(MthDescCheckedBuilderP<MR, N, CN0> builder, TFloat paramType) {
			builder.paramTypes.add(paramType.type());
			return (MthDescCheckedBuilderP) builder;
		}

		/**
		 * Specify a double parameter type
		 * 
		 * @param <MR> the method return type
		 * @param <N> the actual parameter types specified so far
		 * @param <CN1> the boxed parameter types remaining
		 * @param <CN0> the boxed type for the parameter whose type is being specified
		 * @param builder the builder
		 * @param paramType the specified parameter type
		 * @return the builder
		 */
		@SuppressWarnings({ "rawtypes", "unchecked" })
		public static <MR extends BType, N extends Next, CN1 extends CkNext,
			CN0 extends CkEnt<CN1, Double>> MthDescCheckedBuilderP<MR, Ent<N, TDouble>, CN1>
				param(MthDescCheckedBuilderP<MR, N, CN0> builder, TDouble paramType) {
			builder.paramTypes.add(paramType.type());
			return (MthDescCheckedBuilderP) builder;
		}

		/**
		 * Finish building the method descriptor (checked)
		 * <p>
		 * This cannot be invoked until the (boxed) parameter types remaining is empty
		 * 
		 * @param <MR> the method return type
		 * @param <N> the actual parameter types, all specified
		 * @param builder the builder with no remaining boxed (unspecified) parameter types
		 * @return the method descriptor
		 */
		public static <MR extends BType, N extends Next> MthDesc<MR, N>
				build(MthDescCheckedBuilderP<MR, N, CkBot> builder) {
			return new MthDesc<>(
				Type.getMethodDescriptor(builder.retType, builder.paramTypes.toArray(Type[]::new)));
		}
	}

	/**
	 * An unchecked builder of a method descriptor
	 * 
	 * @param <MR> the (machine) return type
	 * @param <N> the parameter (machine) types specified so far, encoded as in {@link Emitter}.
	 */
	public static class MthDescBuilder<MR extends BType, N extends Next> {
		private final Type retType;
		private final List<Type> paramTypes = new ArrayList<>();

		MthDescBuilder(Type retType) {
			this.retType = retType;
		}

		/**
		 * Add a parameter (to the right)
		 * 
		 * @param <P> the type of the parameter
		 * @param paramType the type of the parameter
		 * @return the builder
		 */
		@SuppressWarnings({ "unchecked", "rawtypes" })
		public <P extends BNonVoid> MthDescBuilder<MR, Ent<N, P>> param(P paramType) {
			paramTypes.add(paramType.type());
			return (MthDescBuilder) this;
		}

		/**
		 * Add a parameter (to the right)
		 * 
		 * @param paramType the (source) type of the parameter
		 * @return the builder
		 */
		@SuppressWarnings({ "unchecked", "rawtypes" })
		public MthDescBuilder<MR, Ent<N, TInt>> param(SType paramType) {
			paramTypes.add(paramType.type());
			return (MthDescBuilder) this;
		}

		/**
		 * Finished building the method descriptor
		 * 
		 * @return the method descriptor
		 */
		public MthDesc<MR, N> build() {
			return new MthDesc<>(
				Type.getMethodDescriptor(retType, paramTypes.toArray(Type[]::new)));
		}
	}

	/**
	 * The analog of {@link Next}, but for unspecified parameter types to be checked
	 */
	interface CkNext {
	}

	/**
	 * The analog of {@link Ent}, but for {@link CkNext}
	 * 
	 * @param <N> the tail of the list
	 * @param <T> the (possibly boxed) parameter type
	 */
	interface CkEnt<N extends CkNext, T> extends CkNext {
	}

	/**
	 * The analog of {@link Bot}, but for {@link CkNext}
	 */
	interface CkBot extends CkNext {
	}

	/**
	 * A checked builder (stage 1) of a method descriptor
	 * <p>
	 * Only {@link MthDesc#returns(BType)} or similar may be used on this stage 1 builder.
	 * 
	 * @param <CR> the return type to be specified later with checking
	 * @param <CN> the parameter types to be specified later with checking
	 */
	public static class MthDescCheckedBuilderR<CR, CN extends CkNext> {

		/*package*/ MthDescCheckedBuilderR() {
		}

		/**
		 * A syntactic workaround for static method chaining
		 * 
		 * @param <R> the return type of {@code func}
		 * @param <A1> the first argument type of {@code func}
		 * @param func the method to invoke
		 * @param arg1 the first argument to {@code func}
		 * @return the return value from {@code func}
		 */
		public <R, A1> R check(BiFunction<? super MthDescCheckedBuilderR<CR, CN>, A1, R> func,
				A1 arg1) {
			return func.apply(this, arg1);
		}
	}

	/**
	 * A checked builder (stage 2) of a method descriptor
	 * <p>
	 * Only {@link MthDesc#param(MthDescCheckedBuilderP, TRef)} or similar and
	 * {@link MthDesc#build(MthDescCheckedBuilderP)} may be used on this stage 2 builder.
	 * 
	 * @param <MR> the method return type
	 * @param <N> the actual parameter types specified so far, encoded as in {@link Emitter}.
	 * @param <CN> the boxed parameter types remaining to be specified, encoded similarly to
	 *            {@link Emitter}, but using {@link CkNext} and in reverse order.
	 */
	public static class MthDescCheckedBuilderP<MR extends BType, N extends Next,
		CN extends CkNext> {
		private final Type retType;
		private final List<Type> paramTypes = new ArrayList<>();

		MthDescCheckedBuilderP(Type retType) {
			this.retType = retType;
		}

		/**
		 * A syntactic workaround for static method chaining
		 * 
		 * @param <R> the return type of {@code func}
		 * @param func the method to invoke
		 * @return the return value from {@code func}
		 */
		public <R> R check(Function<? super MthDescCheckedBuilderP<MR, N, CN>, R> func) {
			return func.apply(this);
		}

		/**
		 * A syntactic workaround for static method chaining
		 * 
		 * @param <R> the return type of {@code func}
		 * @param <A1> the first argument type of {@code func}
		 * @param func the method to invoke
		 * @param arg1 the first argument to {@code func}
		 * @return the return value from {@code func}
		 */
		public <R, A1> R check(BiFunction<? super MthDescCheckedBuilderP<MR, N, CN>, A1, R> func,
				A1 arg1) {
			return func.apply(this, arg1);
		}
	}

	/**
	 * An invocation object to facilitate the checked popping of arguments for a static method
	 * invocation and the final push of its returned value.
	 * 
	 * @param <MR> the return type
	 * @param <SN> the contents of the JVM stack
	 * @param <MN> the unmatched parameters types remaining
	 * @param em the emitter, which will be given back when the invocation check is complete
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public record Inv<MR extends BType, SN extends Next, MN extends Next>(Emitter<SN> em) {

		/**
		 * Pop an argument and match/check it against the next (right-most unmatched) parameter
		 * <p>
		 * NOTE: This will not work for polymorphic arguments. For ref-typed arguments, use
		 * {@link #takeRefArg(Inv)}.
		 * 
		 * @param <P1> the parameter type popped from the remaining parameter types
		 * @param <A1> the argument type popped from the stack contents
		 * @param <MR> the return type
		 * @param <MN1> the new remaining parameter types
		 * @param <MN0> the current parameter types having the popped parameter on top
		 * @param <SN1> the new remaining stack contents
		 * @param <SN0> the current stack contents having the popped argument on top
		 * @param inv the invocation object
		 * @return the invocation object with remaining parameters and stack contents
		 */
		public static <P1 extends BNonVoid, A1 extends P1, MR extends BType,
			MN1 extends Next, MN0 extends Ent<MN1, P1>,
			SN1 extends Next, SN0 extends Ent<SN1, A1>> Inv<MR, SN1, MN1>
				takeArg(Inv<MR, SN0, MN0> inv) {
			return (Inv) inv;
		}

		/**
		 * Pop an argument and a parameter without checking
		 * <p>
		 * NOTE: This should only be used with {@link MthDesc#reflect(Method)}. When dealing with a
		 * parameter list whose length is only known at runtime, recursion should be favored, so
		 * that each argument pushed by the emitter is provably paired with a parameter denoted by
		 * calling this method.
		 * 
		 * @param <MR> the return type
		 * @param <SN1> the new remaining stack contents
		 * @param <SN0> the current stack contents having the popped argument on top
		 * @param inv the invocation object
		 * @return the invocation object with remaining parameters and stack contents
		 */
		public static <MR extends BType, SN1 extends Next, SN0 extends Ent<SN1, ?>> Inv<MR, SN1, ?>
				takeQArg(Inv<MR, SN0, ?> inv) {
			return (Inv) inv;
		}

		/**
		 * Pop a polymorphic reference argument and match/check it against the next (right-most
		 * unmatched parameter)
		 * 
		 * @param <PT> the parameter's object type
		 * @param <AT> the argument's object type
		 * @param <P1> the parameter type popped from the remaining parameter types
		 * @param <A1> the argument type popped from the stack contents
		 * @param <MR> the return type
		 * @param <MN1> the new remaining parameter types
		 * @param <MN0> the current parameter types having the popped parameter on top
		 * @param <SN1> the new remaining stack contents
		 * @param <SN0> the current stack contents having the popped argument on top
		 * @param inv the invocation object
		 * @return the invocation object with remaining parameters and stack contents
		 */
		public static <PT, AT extends PT, P1 extends TRef<PT>, A1 extends TRef<AT>,
			MR extends BType,
			MN1 extends Next, MN0 extends Ent<MN1, P1>,
			SN1 extends Next, SN0 extends Ent<SN1, A1>> Inv<MR, SN1, MN1>
				takeRefArg(Inv<MR, SN0, MN0> inv) {
			return (Inv) inv;
		}

		/**
		 * Pop an argument and match/check it against the next (right-most unmatched) parameter
		 * <p>
		 * NOTE: This will not work for polymorphic arguments. For ref-typed arguments, use
		 * {@link #takeRefArg(ObjInv)}.
		 * 
		 * @param <OT> the method's owning type
		 * @param <P1> the parameter type popped from the remaining parameter types
		 * @param <A1> the argument type popped from the stack contents
		 * @param <MR> the return type
		 * @param <MN1> the new remaining parameter types
		 * @param <MN0> the current parameter types having the popped parameter on top
		 * @param <SN1> the new remaining stack contents
		 * @param <SN0> the current stack contents having the popped argument on top
		 * @param inv the invocation object
		 * @return the invocation object with remaining parameters and stack contents
		 */
		public static <OT, P1 extends BNonVoid, A1 extends P1, MR extends BType,
			MN1 extends Next, MN0 extends Ent<MN1, P1>,
			SN1 extends Next, SN0 extends Ent<SN1, A1>> ObjInv<MR, OT, SN1, MN1>
				takeArg(ObjInv<MR, OT, SN0, MN0> inv) {
			return (ObjInv) inv;
		}

		/**
		 * Pop a polymorphic reference argument and match/check it against the next (right-most
		 * unmatched parameter)
		 * 
		 * @param <OT> the method's owning type
		 * @param <PT> the parameter's object type
		 * @param <AT> the argument's object type
		 * @param <P1> the parameter type popped from the remaining parameter types
		 * @param <A1> the argument type popped from the stack contents
		 * @param <MR> the return type
		 * @param <MN1> the new remaining parameter types
		 * @param <MN0> the current parameter types having the popped parameter on top
		 * @param <SN1> the new remaining stack contents
		 * @param <SN0> the current stack contents having the popped argument on top
		 * @param inv the invocation object
		 * @return the invocation object with remaining parameters and stack contents
		 */
		public static <OT, PT, AT extends PT, P1 extends TRef<PT>, A1 extends TRef<AT>,
			MR extends BType,
			MN1 extends Next, MN0 extends Ent<MN1, P1>,
			SN1 extends Next, SN0 extends Ent<SN1, A1>> ObjInv<MR, OT, SN1, MN1>
				takeRefArg(ObjInv<MR, OT, SN0, MN0> inv) {
			return (ObjInv) inv;
		}

		/**
		 * Pop an argument and a parameter without checking
		 * <p>
		 * NOTE: This should only be used with {@link MthDesc#reflect(Method)}. When dealing with a
		 * parameter list whose length is only known at runtime, recursion should be favored, so
		 * that each argument pushed by the emitter is provably paired with a parameter denoted by
		 * calling this method.
		 * 
		 * @param <OT> the method's owning type
		 * @param <MR> the return type
		 * @param <SN1> the new remaining stack contents
		 * @param <SN0> the current stack contents having the popped argument on top
		 * @param inv the invocation object
		 * @return the invocation object with remaining parameters and stack contents
		 */
		public static <OT, MR extends BType, SN1 extends Next, SN0 extends Ent<SN1, ?>>
				ObjInv<MR, OT, SN1, ?> takeQArg(ObjInv<MR, OT, SN0, ?> inv) {
			return (ObjInv) inv;
		}

		/**
		 * Pop the object reference from the stack and check it against the owning type
		 * <p>
		 * This must be used, but only once the parameter type list is empty
		 * 
		 * @param <OT> the method's owning type
		 * @param <MR> the return type
		 * @param <SN1> the new remaining stack contents
		 * @param <SN0> the current stack contents having popped the reference on top
		 * @param inv the invocation object
		 * @return the invocation object with remaining stack contents
		 */
		public static <OT, MR extends BType, SN1 extends Next,
			SN0 extends Ent<SN1, ? extends TRef<? extends OT>>> Inv<MR, SN1, Bot>
				takeObjRef(ObjInv<MR, OT, SN0, Bot> inv) {
			return new Inv(inv.em);
		}

		/**
		 * Pop the object reference from the stack without checking it
		 * <p>
		 * NOTE: This should only be used with {@link MthDesc#reflect(Method)}. This must be used,
		 * but only when sufficient arguments have been popped to satisfy the reflected parameters.
		 * It is up to the caller to know how many arguments are expected.
		 * 
		 * @param <OT> the method's owning type
		 * @param <MR> the return type
		 * @param <SN1> the new remaining stack contents
		 * @param <SN0> the current stack contents having popped the reference on top
		 * @param inv the invocation object
		 * @return the invocation object with remaining stack contents
		 */
		public static <OT, MR extends BType, SN1 extends Next,
			SN0 extends Ent<SN1, ? extends TRef<? extends OT>>> Inv<MR, SN1, Bot>
				takeQObjRef(ObjInv<MR, OT, SN0, ?> inv) {
			return new Inv(inv.em);
		}

		/**
		 * Finish checking an invocation of a static void method
		 * 
		 * @param <SN> the stack contents after the invocation
		 * @param inv the invocation object
		 * @return the emitter typed with the resulting stack
		 */
		public static <SN extends Next> Emitter<SN> retVoid(Inv<TVoid, SN, Bot> inv) {
			return inv.em;
		}

		/**
		 * Finish an invocation of a static void method without checking
		 * <p>
		 * NOTE: This should only be used with {@link MthDesc#reflect(Method)}.
		 * 
		 * @param <SN> the stack contents after the invocation
		 * @param inv the invocation object
		 * @return the emitter typed with the resulting stack
		 */
		public static <SN extends Next> Emitter<SN> retQVoid(Inv<?, SN, ?> inv) {
			return inv.em;
		}

		/**
		 * Finish checking an invocation of a static method
		 * 
		 * @param <MR> the return type
		 * @param <SN> the stack contents before pushing the returned result
		 * @param inv the invocation object
		 * @return the emitter typed with the resulting stack, i.e., having pushed the returned
		 *         value
		 */
		public static <MR extends BNonVoid, SN extends Next> Emitter<Ent<SN, MR>>
				ret(Inv<MR, SN, Bot> inv) {
			return (Emitter) inv.em;
		}

		/**
		 * Finish invocation of a static method without checking
		 * <p>
		 * NOTE: This should only be used with {@link MthDesc#reflect(Method)}.
		 * 
		 * @param <RT> the asserted return type
		 * @param <SN> the stack contents before pushing the returned result
		 * @param inv the invocation object
		 * @param returnType the asserted return type
		 * @return the emitter typed with the resulting stack, i.e., having pushed the returned
		 *         value
		 */
		public static <RT extends BNonVoid, SN extends Next> Emitter<Ent<SN, RT>>
				retQ(Inv<?, SN, ?> inv, RT returnType) {
			return (Emitter) inv.em;
		}

		/**
		 * A syntactic workaround for static method chaining
		 * 
		 * @param <R> the return type of {@code func}
		 * @param func the method to invoke
		 * @return the return value from {@code func}
		 */
		public <R> R step(Function<? super Inv<MR, SN, MN>, R> func) {
			return func.apply(this);
		}

		/**
		 * A syntactic workaround for static method chaining
		 * 
		 * @param <R> the return type of {@code func}
		 * @param <A1> the first argument type of {@code func}
		 * @param func the method to invoke
		 * @param arg1 the first argument to {@code func}
		 * @return the return value from {@code func}
		 */
		public <R, A1> R step(BiFunction<? super Inv<MR, SN, MN>, A1, R> func, A1 arg1) {
			return func.apply(this, arg1);
		}
	}

	/**
	 * An invocation object to facilitate the checked popping of arguments for an instance method
	 * invocation and the final push of its returned value.
	 * 
	 * @param <OT> the method's owning type
	 * @param <MR> the return type
	 * @param <SN> the contents of the JVM stack
	 * @param <MN> the unmatched parameters types remaining
	 * @param em the emitter, which will be given back when the invocation check is complete
	 */
	public record ObjInv<MR extends BType, OT, SN extends Next, MN extends Next>(Emitter<SN> em) {

		/**
		 * A syntactic workaround for static method chaining
		 * 
		 * @param <R> the return type of {@code func}
		 * @param func the method to invoke
		 * @return the return value from {@code func}
		 */
		public <R> R step(Function<? super ObjInv<MR, OT, SN, MN>, R> func) {
			return func.apply(this);
		}
	}

	/**
	 * A defined parameter, which was checked against a method descriptor
	 * 
	 * @param <T> the (machine) type
	 * @param type the type
	 * @param name the name
	 * @param receiver a callback to receive the declared local, once all parameters are defined and
	 *            checked
	 */
	record MthParam<T extends BNonVoid>(T type, String name, Consumer<Local<T>> receiver) {

		void declare(Scope scope) {
			receiver.accept(scope.decl(type, name));
		}
	}

	/**
	 * A static method definition (builder)
	 * 
	 * @param <MR> the return type
	 * @param <N> the parameter types, encoded as in {@link Emitter}
	 * @param em the emitter to be given once method definition moves into bytecode generation
	 * @param params the defined parameters so far
	 */
	record Def<MR, N>(Emitter<Bot> em, List<MthParam<?>> params) {

		/**
		 * A method reference for defining a parameter
		 * 
		 * @param <A0> the method definition
		 * @param <T1> the type of the parameter
		 * @param <R> the return type
		 */
		public interface ParamFunction<A0, T1 extends BNonVoid, R> {
			R apply(A0 arg0, T1 type, String name, Consumer<Local<T1>> receiver);
		}

		/**
		 * A method reference for finishing a static method definition
		 * 
		 * @param <A0> the method definition
		 * @param <R> the return type
		 */
		public interface DoneFunction<A0, R> {
			R apply(A0 arg);
		}

		/**
		 * A method reference for finishing an instance method definition
		 * 
		 * @param <A0> the method definition
		 * @param <OT> the owning type
		 * @param <R> the return type
		 */
		public interface ThisFunction<A0, OT, R> {
			R apply(A0 arg0, TRef<OT> type, Consumer<Local<TRef<OT>>> receiver);
		}

		/**
		 * Define a parameter for a static method
		 * 
		 * @param <MR> the return type
		 * @param <T1> the parameter type
		 * @param <N1> the remaining parameters still requiring definition
		 * @param <N0> the parameters remaining and the one being defined
		 * @param mdef the method definition
		 * @param type the parameter type
		 * @param name the name
		 * @param receiver a consumer to accept the declared local variable handle
		 * @return the method definition
		 */
		@SuppressWarnings({ "unchecked", "rawtypes" })
		public static <MR extends BType, T1 extends BNonVoid, N1 extends Next,
			N0 extends Ent<N1, T1>> Def<MR, N1> param(Def<MR, N0> mdef, T1 type, String name,
					Consumer<Local<T1>> receiver) {
			mdef.params.add(new MthParam<>(type, name, receiver));
			return (Def) mdef;
		}

		/**
		 * Define a parameter for an instance method
		 * 
		 * @param <MR> the return type
		 * @param <OT> the owning type
		 * @param <T1> the parameter type
		 * @param <N1> the remaining parameters still requiring definition
		 * @param <N0> the parameters remaining and the one being defined
		 * @param mdef the method definition
		 * @param type the parameter type
		 * @param name the name
		 * @param receiver a consumer to accept the declared local variable handle
		 * @return the method definition
		 */
		@SuppressWarnings({ "unchecked", "rawtypes" })
		public static <MR extends BType, OT, T1 extends BNonVoid, N1 extends Next,
			N0 extends Ent<N1, T1>> ObjDef<MR, OT, N1> param(ObjDef<MR, OT, N0> mdef, T1 type,
					String name, Consumer<Local<T1>> receiver) {
			mdef.params.add(new MthParam<>(type, name, receiver));
			return (ObjDef) mdef;
		}

		/**
		 * Finish defining a static method and begin emitting bytecode
		 * 
		 * @param <MR> the return type
		 * @param mdef the method definition
		 * @return the return request and emitter typed with an empty stack
		 */
		public static <MR extends BType> RetReqEm<MR> done(Def<MR, Bot> mdef) {
			return new RetReqEm<>(new RetReq<>(), mdef.em);
		}

		/**
		 * Finish defining an instance method and begin emitting bytecode
		 * 
		 * @param <MR> the return type
		 * @param <OT> the owning type
		 * @param mdef the method definition
		 * @param type the owning type (for this {@code this}) parameter
		 * @param receiver a consumer to accept the declared {@code this} local handle
		 * @return the return request and emitter typed with an empty stack
		 */
		public static <MR extends BType, OT> RetReqEm<MR> done(ObjDef<MR, OT, Bot> mdef,
				TRef<OT> type, Consumer<Local<TRef<OT>>> receiver) {
			mdef.params.add(new MthParam<>(type, "this", receiver));
			Scope scope = mdef.em.rootScope;
			List<MthParam<?>> params = mdef.params.reversed();
			for (int i = 0; i < params.size(); i++) {
				params.get(i).declare(scope);
			}
			return new RetReqEm<>(new RetReq<>(), mdef.em);
		}

		/**
		 * A syntactic workaround for static method chaining
		 * 
		 * @param <R> the return type of {@code func}
		 * @param <T1> the parameter type
		 * @param func the static method reference that actually processes the parameter
		 * @param type the parameter type
		 * @param name the name
		 * @param receiver the receiver
		 * @return the return value from {@code func}
		 */
		public <R, T1 extends BNonVoid> R param(ParamFunction<? super Def<MR, N>, T1, R> func,
				T1 type, String name, Consumer<Local<T1>> receiver) {
			return func.apply(this, type, name, receiver);
		}

		/**
		 * A syntactic workaround for static method chaining
		 * 
		 * @param <R> the return type of {@code func}
		 * @param func the static method reference
		 * @return the return value from {@code func}
		 */
		public <R> R param(DoneFunction<? super Def<MR, N>, R> func) {
			return func.apply(this);
		}
	}

	/**
	 * An instance method definition (builder)
	 * 
	 * @param <MR> the return type
	 * @param <OT> the owning type
	 * @param <N> the parameter types, encoded as in {@link Emitter}
	 * @param em the emitter to be given once method definition moves into bytecode generation
	 * @param params the defined parameters so far
	 */
	record ObjDef<MR, OT, N>(Emitter<Bot> em, List<MthParam<?>> params) {

		/**
		 * A syntactic workaround for static method chaining
		 * 
		 * @param <R> the return type of {@code func}
		 * @param <T1> the parameter type
		 * @param func the static method reference that actually processes the parameter
		 * @param type the parameter type
		 * @param name the name
		 * @param receiver the receiver
		 * @return the return value from {@code func}
		 */
		public <R, T1 extends BNonVoid> R param(
				ParamFunction<? super ObjDef<MR, OT, N>, T1, R> func, T1 type, String name,
				Consumer<Local<T1>> receiver) {
			return func.apply(this, type, name, receiver);
		}

		/**
		 * A syntactic workaround for static method chaining
		 * 
		 * @param <R> the return type of {@code func}
		 * @param func the static method reference that actually processes the parameter
		 * @param type the {@code this} type
		 * @param receiver the receiver
		 * @return the return value from {@code func}
		 */
		public <R> R param(ThisFunction<? super ObjDef<MR, OT, N>, OT, R> func, TRef<OT> type,
				Consumer<Local<TRef<OT>>> receiver) {
			return func.apply(this, type, receiver);
		}
	}

	/**
	 * A return request
	 * <p>
	 * This is just a witness to the required return type of a method. Technically, there's nothing
	 * that prevents a user from passing a request meant for one method into, e.g.,
	 * {@link Op#return_(Emitter, RetReq)} for bytecode emitted into another, but such should be
	 * unlikely to happen accidentally.
	 * 
	 * @param <T> the required return type
	 */
	record RetReq<T extends BType>() {};

	/**
	 * A tuple of return request and emitter with empty stack
	 * 
	 * @param <T> the required return type
	 */
	record RetReqEm<T extends BType>(RetReq<T> ret, Emitter<Bot> em) {}
}
