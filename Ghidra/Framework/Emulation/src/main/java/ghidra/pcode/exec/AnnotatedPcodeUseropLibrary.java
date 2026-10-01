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
package ghidra.pcode.exec;

import java.lang.annotation.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.reflect.*;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.lang3.reflect.TypeUtils;

import ghidra.lifecycle.Experimental;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.SleighPcodeUseropDefinition.BuilderStage1;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import utilities.util.AnnotationUtilities;

/**
 * A userop library wherein Java methods are exported via a special annotation
 * <p>
 * See {@code StandAloneEmuExampleScript} for an example of implementing a userop library.
 *
 * @param <T> the type of data processed by the library
 */
public abstract class AnnotatedPcodeUseropLibrary<T> extends DefaultPcodeUseropLibrary<T> {
	private static final Map<Class<?>, Set<Method>> CACHE_BY_CLASS = new HashMap<>();

	private static Set<Method> collectDefinitions(
			Class<? extends AnnotatedPcodeUseropLibrary<?>> cls) {
		return AnnotationUtilities.collectAnnotatedMethods(PcodeUserop.class, cls);
	}

	private enum ParamAnnotProc {
		EXECUTOR(OpExecutor.class, PcodeExecutor.class) {
			@Override
			int getPos(AnnotatedPcodeUseropDefinition<?> opdef) {
				return opdef.posExecutor;
			}

			@Override
			void setPos(AnnotatedPcodeUseropDefinition<?> opdef, int pos) {
				opdef.posExecutor = pos;
			}
		},
		STATE(OpState.class, PcodeExecutorState.class) {
			@Override
			int getPos(AnnotatedPcodeUseropDefinition<?> opdef) {
				return opdef.posState;
			}

			@Override
			void setPos(AnnotatedPcodeUseropDefinition<?> opdef, int pos) {
				opdef.posState = pos;
			}
		},
		LIBRARY(OpLibrary.class, PcodeUseropLibrary.class) {
			@Override
			int getPos(AnnotatedPcodeUseropDefinition<?> opdef) {
				return opdef.posLib;
			}

			@Override
			void setPos(AnnotatedPcodeUseropDefinition<?> opdef, int pos) {
				opdef.posLib = pos;
			}
		},
		OUTPUT(OpOutput.class, Varnode.class, int[].class) {
			@Override
			int getPos(AnnotatedPcodeUseropDefinition<?> opdef) {
				return opdef.posOut;
			}

			@Override
			void setPos(AnnotatedPcodeUseropDefinition<?> opdef, int pos) {
				opdef.posOut = pos;
			}
		},
		OP(OpOp.class, PcodeOp.class) {
			@Override
			int getPos(AnnotatedPcodeUseropDefinition<?> opdef) {
				return opdef.posOp;
			}

			@Override
			void setPos(AnnotatedPcodeUseropDefinition<?> opdef, int pos) {
				opdef.posOp = pos;
			}
		};

		static boolean processParameter(AnnotatedPcodeUseropDefinition<?> opdef, Type declClsOpType,
				int i, Parameter p) {
			ParamAnnotProc only = null;
			for (ParamAnnotProc proc : ParamAnnotProc.values()) {
				if (proc.hasAnnot(p)) {
					if (only != null) {
						throw new IllegalArgumentException("Parameter can have at most one of " +
							Stream.of(ParamAnnotProc.values())
									.map(pr -> "@" + pr.annotCls.getSimpleName())
									.collect(Collectors.toList()));
					}
					only = proc;
				}
			}
			if (only == null) {
				return false;
			}
			only.processParameterPerAnnot(opdef, declClsOpType, i, p);
			return true;
		}

		private final Class<? extends Annotation> annotCls;
		private final List<Class<?>> allowedClsList;

		private ParamAnnotProc(Class<? extends Annotation> annotCls, Class<?>... paramCls) {
			this.annotCls = annotCls;
			this.allowedClsList = List.of(paramCls);
		}

		abstract int getPos(AnnotatedPcodeUseropDefinition<?> opdef);

		abstract void setPos(AnnotatedPcodeUseropDefinition<?> opdef, int pos);

		boolean hasAnnot(Parameter p) {
			return p.getAnnotation(annotCls) != null;
		}

		static Type parameterize(Class<?> paramCls, Type opType) {
			TypeVariable<?>[] typeParams = paramCls.getTypeParameters();
			if (typeParams.length == 0) {
				return paramCls;
			}
			if (typeParams.length == 1) {
				return TypeUtils.parameterize(paramCls, opType);
			}
			throw new AssertionError();
		}

		String nameAllowedArgumentTypes(Type opType) {
			return allowedClsList.stream()
					.map(cls -> parameterize(cls, opType).toString())
					.collect(Collectors.joining(","));
		}

		record MatchedClassWithArgs(Class<?> paramCls, Map<TypeVariable<?>, Type> typeArgs) {
			static MatchedClassWithArgs find(Type paramType, List<Class<?>> allowed) {
				for (Class<?> cls : allowed) {
					Map<TypeVariable<?>, Type> typeArgs =
						TypeUtils.getTypeArguments(paramType, cls);
					if (typeArgs != null) {
						return new MatchedClassWithArgs(cls, typeArgs);
					}
				}
				return null;
			}
		}

		void processParameterPerAnnot(AnnotatedPcodeUseropDefinition<?> opdef, Type declClsOpType,
				int i, Parameter p) {
			if (getPos(opdef) != -1) {
				throw new IllegalArgumentException(
					"Can only have one parameter with @" + annotCls.getSimpleName());
			}
			Type pType = p.getParameterizedType();
			MatchedClassWithArgs match = MatchedClassWithArgs.find(pType, allowedClsList);
			if (match == null) {
				throw new IllegalArgumentException("Parameter " + p.getName() + " with @" +
					annotCls.getSimpleName() + " must acccept " +
					nameAllowedArgumentTypes(declClsOpType));
			}
			if (match.typeArgs.isEmpty()) {
				// Nothing
			}
			else if (match.typeArgs.size() == 1) {
				Type declMthOpType = match.typeArgs.get(match.paramCls.getTypeParameters()[0]);
				if (!Objects.equals(declClsOpType, declMthOpType)) {
					throw new IllegalArgumentException("Parameter " + p.getName() + " with @" +
						annotCls.getSimpleName() + " must acccept " +
						nameAllowedArgumentTypes(declClsOpType));
				}
			}
			else {
				throw new AssertionError("Internal: paramCls for @" + annotCls.getSimpleName() +
					"should only have one type parameter <T>");
			}
			setPos(opdef, i);
		}
	}

	/**
	 * A wrapped, annotated Java method, exported as a userop definition
	 *
	 * @param <T> the type of data processed by the userop
	 */
	protected static abstract class AnnotatedPcodeUseropDefinition<T>
			implements PcodeUseropDefinition<T> {
		static final Class<?>[] REQUIRED_SLEIGH_DEF_PARAMS = new Class<?>[] {
			SleighPcodeUseropDefinition.BuilderStage1.class };

		protected static boolean isPrimitive(Type type) {
			return type instanceof Class<?> cls && cls.isPrimitive();
		}

		protected static <T> PcodeUseropDefinition<T> create(PcodeUserop annot,
				AnnotatedPcodeUseropLibrary<T> library, Type opType, Lookup lookup, Method method) {
			Class<?> returnType = method.getReturnType();
			if (SleighPcodeUseropDefinition.class.isAssignableFrom(returnType)) {
				if (!Arrays.equals(REQUIRED_SLEIGH_DEF_PARAMS, method.getParameterTypes())) {
					throw new IllegalArgumentException("""
							Method %s with @%s annotation returning a %s must only accept these \
							parameters: %s""".formatted(method.getName(),
						PcodeUserop.class.getSimpleName(),
						SleighPcodeUseropDefinition.class.getSimpleName(),
						List.of(REQUIRED_SLEIGH_DEF_PARAMS)));
				}
				try {
					SleighPcodeUseropDefinition def =
						(SleighPcodeUseropDefinition) method.invoke(library,
							SleighPcodeUseropDefinition.FACTORY.define(method.getName()));
					return def.cast();
				}
				catch (IllegalAccessException | InvocationTargetException e) {
					throw new RuntimeException(e);
				}
			}
			if (annot.variadic()) {
				return new VariadicAnnotatedPcodeUseropDefinition<>(library, opType, lookup,
					method, annot);
			}
			return new FixedArgsAnnotatedPcodeUseropDefinition<>(library, opType, lookup,
				method, annot);
		}

		@SuppressWarnings("unchecked")
		protected static <T> T fromPrimitive(Object value, int size, boolean signed,
				PcodeArithmetic<T> arithmetic) {
			return switch (value) {
				case null -> null;
				case Byte v -> signed
						? arithmetic.fromConstSigned(v, size)
						: arithmetic.fromConst(v, size);
				case Short v -> signed
						? arithmetic.fromConstSigned(v, size)
						: arithmetic.fromConst(v, size);
				case Integer v -> signed
						? arithmetic.fromConstSigned(v, size)
						: arithmetic.fromConst(v, size);
				case Long v -> signed
						? arithmetic.fromConstSigned(v, size)
						: arithmetic.fromConst(v, size);
				case Float v -> arithmetic.fromConst(v, size);
				case Double v -> arithmetic.fromConst(v, size);
				case Boolean v -> arithmetic.fromConst(v, size);
				default -> (T) value;
			};
		}

		protected final Method method;
		private final AnnotatedPcodeUseropLibrary<T> library;
		private final boolean isFunctional;
		private final boolean canInterrupt;
		private final boolean hasSideEffects;
		private final boolean modifiesContext;
		private final boolean canInline;
		private final boolean signed;
		private final MethodHandle handle;

		private int posExecutor = -1;
		private int posState = -1;
		private int posLib = -1;
		private int posOut = -1;
		private int posOp = -1;

		public AnnotatedPcodeUseropDefinition(AnnotatedPcodeUseropLibrary<T> library, Type opType,
				Lookup lookup, Method method, PcodeUserop annot) {
			initStarting();
			this.method = method;
			this.library = library;
			try {
				MethodHandle unbound = lookup.unreflect(method);
				if (Modifier.isStatic(method.getModifiers())) {
					this.handle = unbound;
				}
				else {
					this.handle = lookup.unreflect(method).bindTo(library);
				}
			}
			catch (IllegalAccessException e) {
				throw new IllegalArgumentException(
					"Cannot access " + method + " having @" +
						PcodeUserop.class.getSimpleName() +
						" annotation. Override getMethodLookup()");
			}
			Type declClsOpType = PcodeUseropLibrary.getOperandType(method.getDeclaringClass());
			Type rType = method.getGenericReturnType();
			if (!isPrimitive(rType) && !TypeUtils.isAssignable(rType, declClsOpType) ||
				rType == char.class) {
				throw new IllegalArgumentException("""
						Method %s with @%s annotation must return a non-char primitive type, \
						void, or a type assignable to %s.""".formatted(
					method.getName(), PcodeUserop.class.getSimpleName(), declClsOpType));
			}

			Parameter[] params = method.getParameters();
			for (int i = 0; i < params.length; i++) {
				Parameter p = params[i];
				boolean processed = ParamAnnotProc.processParameter(this, declClsOpType, i, p);
				if (!processed) {
					processNonAnnotatedParameter(declClsOpType, opType, i, p);
				}
			}
			initFinished();
			this.isFunctional = annot.functional();
			this.canInterrupt = annot.canInterrupt();
			this.hasSideEffects = annot.hasSideEffects();
			this.modifiesContext = annot.modifiesContext();
			this.canInline = annot.canInline();
			this.signed = annot.signed();
		}

		@Override
		public String getName() {
			return method.getName();
		}

		@Override
		public void execute(PcodeExecutor<T> executor, PcodeUseropLibrary<T> library, PcodeOp op,
				Varnode outVar, List<Varnode> inVars) {
			validateInputs(inVars);

			PcodeExecutorStatePiece<T, T> state = executor.getState();
			List<Object> args = Arrays.asList(new Object[method.getParameterCount()]);

			if (posExecutor != -1) {
				args.set(posExecutor, executor);
			}
			if (posState != -1) {
				args.set(posState, state);
			}
			if (posLib != -1) {
				args.set(posLib, library);
			}
			if (posOut != -1) {
				args.set(posOut, outVar);
			}
			if (posOp != -1) {
				args.set(posOp, op);
			}
			placeInputs(executor, args, inVars);

			try {
				Object result = handle.invokeWithArguments(args);
				if (result != null && outVar != null) {
					state.setVar(outVar,
						fromPrimitive(result, outVar.getSize(), signed, executor.getArithmetic()));
				}
			}
			catch (PcodeExecutionException e) {
				throw e;
			}
			catch (Throwable e) {
				throw new PcodeExecutionException("Error executing userop", null, e);
			}
		}

		@Override
		public boolean isFunctional() {
			return isFunctional;
		}

		@Override
		public boolean canInterrupt() {
			return canInterrupt;
		}

		@Override
		public boolean hasSideEffects() {
			return hasSideEffects;
		}

		@Override
		public boolean modifiesContext() {
			return modifiesContext;
		}

		@Override
		public boolean canInlinePcode() {
			return canInline;
		}

		@Override
		public boolean isOutSigned() {
			return signed;
		}

		@Override
		public Class<?> getOutputType() {
			if (posOut == -1) {
				return method.getReturnType();
			}
			return method.getParameterTypes()[posOut];
		}

		@Override
		public Method getJavaMethod() {
			return method;
		}

		@Override
		public PcodeUseropLibrary<T> getDefiningLibrary() {
			return library;
		}

		protected void initStarting() {
			// Optional override
		}

		protected abstract void processNonAnnotatedParameter(Type declClsOpType, Type opType, int i,
				Parameter p);

		protected void initFinished() {
			// Optional override
		}

		protected void validateInputs(List<Varnode> inVars) throws PcodeExecutionException {
			// Optional override
		}

		protected abstract void placeInputs(PcodeExecutor<T> executor, List<Object> args,
				List<Varnode> inVars);
	}

	/**
	 * An annotated userop with a fixed number of arguments
	 *
	 * @param <T> the type of data processed by the userop
	 */
	protected static class FixedArgsAnnotatedPcodeUseropDefinition<T>
			extends AnnotatedPcodeUseropDefinition<T> {

		interface UseropInputParam {
			int position();

			default boolean signed() {
				return false;
			}

			<T> Object convert(Varnode vn, PcodeExecutor<T> executor);
		}

		record VarnodeUseropInputParam(int position) implements UseropInputParam {
			@Override
			public <T> Object convert(Varnode vn, PcodeExecutor<T> executor) {
				return vn;
			}
		}

		record TValUseropInputParam(int position) implements UseropInputParam {
			@Override
			public <T> Object convert(Varnode vn, PcodeExecutor<T> executor) {
				PcodeExecutorStatePiece<?, ?> state = executor.getState();
				return state.getVar(vn, executor.getReason());
			}
		}

		record ByteUseropInputParam(int position, boolean signed) implements UseropInputParam {
			@Override
			public <T> Object convert(Varnode vn, PcodeExecutor<T> executor) {
				PcodeExecutorStatePiece<T, T> state = executor.getState();
				PcodeArithmetic<T> arithmetic = executor.getArithmetic();
				T t = state.getVar(vn, executor.getReason());
				return (byte) (signed
						? arithmetic.toLongSigned(t, Purpose.OTHER)
						: arithmetic.toLong(t, Purpose.OTHER));
			}
		}

		record ShortUseropInputParam(int position, boolean signed) implements UseropInputParam {
			@Override
			public <T> Object convert(Varnode vn, PcodeExecutor<T> executor) {
				PcodeExecutorStatePiece<T, T> state = executor.getState();
				PcodeArithmetic<T> arithmetic = executor.getArithmetic();
				T t = state.getVar(vn, executor.getReason());
				return (short) (signed
						? arithmetic.toLongSigned(t, Purpose.OTHER)
						: arithmetic.toLong(t, Purpose.OTHER));
			}
		}

		record IntUseropInputParam(int position, boolean signed) implements UseropInputParam {
			@Override
			public <T> Object convert(Varnode vn, PcodeExecutor<T> executor) {
				PcodeExecutorStatePiece<T, T> state = executor.getState();
				PcodeArithmetic<T> arithmetic = executor.getArithmetic();
				T t = state.getVar(vn, executor.getReason());
				return (int) (signed
						? arithmetic.toLongSigned(t, Purpose.OTHER)
						: arithmetic.toLong(t, Purpose.OTHER));
			}
		}

		record LongUseropInputParam(int position, boolean signed) implements UseropInputParam {
			@Override
			public <T> Object convert(Varnode vn, PcodeExecutor<T> executor) {
				PcodeExecutorStatePiece<T, T> state = executor.getState();
				PcodeArithmetic<T> arithmetic = executor.getArithmetic();
				T t = state.getVar(vn, executor.getReason());
				return signed
						? arithmetic.toLongSigned(t, Purpose.OTHER)
						: arithmetic.toLong(t, Purpose.OTHER);
			}
		}

		record IntArrayUseropInputParam(int position) implements UseropInputParam {
			@Override
			public <T> Object convert(Varnode vn, PcodeExecutor<T> executor) {
				PcodeExecutorStatePiece<T, T> state = executor.getState();
				PcodeArithmetic<T> arithmetic = executor.getArithmetic();
				BigInteger value =
					arithmetic.toBigInteger(state.getVar(vn, executor.getReason()), Purpose.OTHER);
				int[] result = new int[(vn.getSize() + 3) / 4];
				// This is terribly slow
				for (int i = 0; i < result.length; i++) {
					result[i] = value.intValue();
					value = value.shiftRight(Integer.SIZE);
				}
				return result;
			}
		}

		record FloatUseropInputParam(int position) implements UseropInputParam {
			@Override
			public <T> Object convert(Varnode vn, PcodeExecutor<T> executor) {
				PcodeExecutorStatePiece<T, T> state = executor.getState();
				PcodeArithmetic<T> arithmetic = executor.getArithmetic();
				return arithmetic.toFloat(state.getVar(vn, executor.getReason()), Purpose.OTHER);
			}
		}

		record DoubleUseropInputParam(int position) implements UseropInputParam {
			@Override
			public <T> Object convert(Varnode vn, PcodeExecutor<T> executor) {
				PcodeExecutorStatePiece<T, T> state = executor.getState();
				PcodeArithmetic<T> arithmetic = executor.getArithmetic();
				return arithmetic.toDouble(state.getVar(vn, executor.getReason()), Purpose.OTHER);
			}
		}

		record BooleanUseropInputParam(int position) implements UseropInputParam {
			@Override
			public <T> Object convert(Varnode vn, PcodeExecutor<T> executor) {
				PcodeExecutorStatePiece<T, T> state = executor.getState();
				PcodeArithmetic<T> arithmetic = executor.getArithmetic();
				return arithmetic.isTrue(state.getVar(vn, executor.getReason()), Purpose.OTHER);
			}
		}

		private List<UseropInputParam> paramsIn;

		public FixedArgsAnnotatedPcodeUseropDefinition(AnnotatedPcodeUseropLibrary<T> library,
				Type opType, Lookup lookup, Method method, PcodeUserop annot) {
			super(library, opType, lookup, method, annot);
		}

		@Override
		protected void initStarting() {
			paramsIn = new ArrayList<>();
		}

		@Override
		protected void processNonAnnotatedParameter(Type declClsOpType, Type opType, int i,
				Parameter p) {
			OpInput annotation = p.getAnnotation(OpInput.class);
			boolean signed = annotation == null ? OpInput.DEFAULT_SIGNED : annotation.signed();
			Type pType = p.getParameterizedType();
			if (TypeUtils.isAssignable(Varnode.class, pType)) {
				paramsIn.add(new VarnodeUseropInputParam(i));
			}
			else if (TypeUtils.isAssignable(declClsOpType, pType)) {
				paramsIn.add(new TValUseropInputParam(i));
			}
			else if (pType == byte.class) {
				paramsIn.add(new ByteUseropInputParam(i, signed));
			}
			else if (pType == short.class) {
				paramsIn.add(new ShortUseropInputParam(i, signed));
			}
			else if (pType == int.class) {
				paramsIn.add(new IntUseropInputParam(i, signed));
			}
			else if (pType == long.class) {
				paramsIn.add(new LongUseropInputParam(i, signed));
			}
			else if (pType == int[].class) {
				paramsIn.add(new IntArrayUseropInputParam(i));
			}
			else if (pType == float.class) {
				paramsIn.add(new FloatUseropInputParam(i));
			}
			else if (pType == double.class) {
				paramsIn.add(new DoubleUseropInputParam(i));
			}
			else if (pType == boolean.class) {
				paramsIn.add(new BooleanUseropInputParam(i));
			}
			else {
				throw new IllegalArgumentException("""
						Input parameter %s of userop %s must be non-char primitive type, \
						%s, or accept %s. Was %s.
						""".formatted(
					p.getName(), method.getName(), Varnode.class.getSimpleName(), declClsOpType,
					pType));
			}
		}

		@Override
		protected void validateInputs(List<Varnode> inVars)
				throws PcodeExecutionException {
			if (inVars.size() != paramsIn.size()) {
				throw new PcodeExecutionException(
					"Incorrect input parameter count for userop " +
						method.getName() + ". Expected " + paramsIn.size() + " but got " +
						inVars.size());
			}
		}

		@Override
		protected void placeInputs(PcodeExecutor<T> executor, List<Object> args,
				List<Varnode> inVars) {
			for (int i = 0; i < paramsIn.size(); i++) {
				UseropInputParam ip = paramsIn.get(i);
				args.set(ip.position(), ip.convert(inVars.get(i), executor));
			}
		}

		@Override
		public int getInputCount() {
			return paramsIn.size();
		}

		@Override
		public boolean isInSigned(int index) {
			return paramsIn.get(index).signed();
		}
	}

	/**
	 * An annotated userop with a variable number of arguments
	 *
	 * @param <T> the type of data processed by the userop
	 */
	protected static class VariadicAnnotatedPcodeUseropDefinition<T>
			extends AnnotatedPcodeUseropDefinition<T> {

		private int posIns;
		private Class<?> opRawType;

		public VariadicAnnotatedPcodeUseropDefinition(AnnotatedPcodeUseropLibrary<T> library,
				Type opType, Lookup lookup, Method method, PcodeUserop annot) {
			super(library, opType, lookup, method, annot);
		}

		@Override
		protected void initStarting() {
			posIns = -1;
			opRawType = null;
		}

		@Override
		protected void processNonAnnotatedParameter(Type declClsOpType, Type opType, int i,
				Parameter p) {
			if (posIns != -1) {
				throw new IllegalArgumentException(
					"Only one non-annotated parameter is allowed to receive the inputs");
			}
			Type pType = p.getParameterizedType();
			Type eType = TypeUtils.getArrayComponentType(pType);
			if (eType == null) {
				throw new IllegalArgumentException(
					"Variadic userop must receive inputs as " + declClsOpType + "[] or " +
						Varnode.class.getSimpleName() + "[]");
			}
			if (pType.equals(Varnode[].class)) {
				// Just pass inVars as is
			}
			else if (TypeUtils.isAssignable(declClsOpType, eType)) {
				this.opRawType = TypeUtils.getRawType(opType, getClass());
			}
			else {
				throw new IllegalArgumentException(
					"Variadic userop must receive inputs as " + declClsOpType + "[] or " +
						Varnode.class.getSimpleName() + "[]");
			}
			posIns = i;
		}

		@Override
		protected void initFinished() {
			if (posIns == -1) {
				throw new IllegalArgumentException(
					"Variadic userop must have a parameter for the inputs");
			}
		}

		protected Object[] readVars(PcodeExecutorState<T> state, List<Varnode> vars,
				Reason reason) {
			Object[] vals = (Object[]) Array.newInstance(opRawType, vars.size());
			for (int i = 0; i < vals.length; i++) {
				vals[i] = state.getVar(vars.get(i), reason);
			}
			return vals;
		}

		@Override
		protected void placeInputs(PcodeExecutor<T> executor, List<Object> args,
				List<Varnode> inVars) {
			if (opRawType != null) {
				args.set(posIns, readVars(executor.getState(), inVars, executor.getReason()));
			}
			else {
				args.set(posIns, inVars.toArray(Varnode[]::new));
			}
		}

		@Override
		public int getInputCount() {
			return -1;
		}

		@Override
		public boolean isInSigned(int index) {
			return false;
		}
	}

	/**
	 * An annotation to export a Java method as a userop in the library.
	 * <p>
	 * This can annotate a Java callback userop or a Sleigh-defined userop.
	 * <p>
	 * For a Java callback, each parameter ordinarily receives an input to the userop. Each
	 * parameter may be annotated with at most one of {@link OpExecutor}, {@link OpState},
	 * {@link OpLibrary}, or {@link OpOutput} to change what it receives. If {@link #variadic()} is
	 * false, non-annotated parameters receive the inputs to the userop in matching order.
	 * Conventionally, annotated parameters should be placed first or last. Parameters accepting
	 * inputs must have type {@link Varnode}, a type assignable from {@code T}, or a primitive type,
	 * and may be annotated with {@link OpInput}. A parameter of type {@link Varnode} will receive
	 * the input {@link Varnode}. A parameter that is of primitive type or assignable from {@code T}
	 * will receive the input value. If it so happens that {@code T} is assignable from
	 * {@link Varnode}, the parameter will receive the {@link Varnode}, not the value. <b>NOTE:</b>
	 * Receiving a value instead of a variable may lose its size. Depending on the type of the
	 * value, that size may or may not be recoverable. Values passed as primitives imply an attempt
	 * to concretize the value.
	 * <p>
	 * If {@link #variadic()} is true, then a single non-annotated parameter receives all inputs in
	 * order. This parameter must have a type {@link Varnode}{@code []} to receive variables or have
	 * type assignable from {@code T[]} to receive values.
	 * <p>
	 * Note that there is no annotation to receive the "thread," because threads are not a concept
	 * known to the p-code executor or userop libraries, in general. In most cases, receiving the
	 * executor and/or state (which are usually bound to a specific thread) is sufficient. The
	 * preferred means of exposing thread-specific userops is to construct a library bound to that
	 * specific thread. That strategy should preserve compile-time type safety. Alternatively, you
	 * can receive the executor or state, cast it to your specific type, and use an accessor to get
	 * its thread.
	 * <p>
	 * For a Sleigh-defined userop, the method must return {@link SleighPcodeUseropDefinition} and
	 * accept a single parameter of type {@link BuilderStage1}. The method is invoked once at
	 * library construction. The method can use the builder to create the userop definition. The
	 * various attributes and attestations accepted by this annotation are currently ignored for
	 * Sleigh-defined userops. The various {@code Op}-prefixed annotations, e.g., {@link OpExecutor}
	 * have no effect on the single parameter and should not be applied.
	 */
	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.METHOD)
	public @interface PcodeUserop {
		/**
		 * Set to true to receive all inputs in an array.
		 */
		boolean variadic() default false;

		/**
		 * Set to true to attest that the userop is a pure function.
		 * <p>
		 * An incorrect attestation can lead to erroneous execution results.
		 * 
		 * @see PcodeUseropLibrary.PcodeUseropDefinition#isFunctional()
		 */
		boolean functional() default false;

		/**
		 * Set to false to attest that the userop will not interrupt execution.
		 * <p>
		 * This defaults to false, even though it seems unsafe to attest to no interrupts.
		 * Generally, this is about <em>expected</em> interruptions, not exceptions that occur
		 * because of buggy userop implementations. In general, userops that interrupt on purpose
		 * are uncommon. Userop authors may, at their discretion, adjust this attribute to ease
		 * debugging. If this userop can throw an exception and the emulator is meant to resume
		 * execution after handling it, this <em>must</em> be set to true.
		 * 
		 * @see PcodeUseropLibrary.PcodeUseropDefinition#canInterrupt()
		 */
		boolean canInterrupt() default false;

		/**
		 * Set to false to attest the userop has no side effects.
		 * <p>
		 * An incorrect attestation can lead to erroneous execution results.
		 * 
		 * @see PcodeUseropLibrary.PcodeUseropDefinition#hasSideEffects()
		 */
		boolean hasSideEffects() default true;

		/**
		 * Set to true to indicate the userop can modify the decode context.
		 * <p>
		 * Failure to indicate context modifications can lead to erroneous decodes and thus
		 * incorrect execution results.
		 * 
		 * @see PcodeUseropLibrary.PcodeUseropDefinition#modifiesContext()
		 */
		boolean modifiesContext() default false;

		/**
		 * Set to true to suggest inlining.
		 * 
		 * @see PcodeUseropLibrary.PcodeUseropDefinition#canInlinePcode()
		 */
		boolean canInline() default false;

		/**
		 * Set true to indicate sign extension of the output.
		 * 
		 * @see PcodeUseropLibrary.PcodeUseropDefinition#isOutSigned()
		 */
		boolean signed() default true;
	}

	/**
	 * An annotation to receive the executor itself into a parameter
	 * <p>
	 * The annotated parameter must have type {@link PcodeExecutor} with the same {@code <T>} as the
	 * class declaring the method.
	 */
	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.PARAMETER)
	public @interface OpExecutor {
	}

	/**
	 * An annotation to receive the executor's state into a parameter
	 * <p>
	 * The annotated parameter must have type {@link PcodeExecutorState} with the same {@code <T>}
	 * as the class declaring the method.
	 */
	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.PARAMETER)
	public @interface OpState {
	}

	/**
	 * An annotation to receive the complete library into a parameter
	 * <p>
	 * Because the library defining the userop may be composed with other libraries, it is not
	 * sufficient to use the "{@code this}" reference to obtain the library. If the library being
	 * used for execution needs to be passed to a dependent component of execution, it must be the
	 * complete library, not just the one defining the userop. This annotation allows a userop
	 * definition to receive the complete library.
	 * <p>
	 * The annotated parameter must have type {@link PcodeUseropLibrary} with the same {@code <T>}
	 * as the class declaring the method.
	 */
	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.PARAMETER)
	public @interface OpLibrary {
	}

	/**
	 * An annotation to receive the output varnode into a parameter
	 * <p>
	 * The annotated parameter must have type {@link Varnode} (or {@code int[]} for direct
	 * invocation when the output is a multi-precision integer}).
	 */
	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.PARAMETER)
	public @interface OpOutput {
	}

	/**
	 * An annotation to receive an input into a parameter
	 * <p>
	 * Parameters without other annotations are assumed inputs, but this annotation permits further
	 * defining the behavior of that input. This is experimental. We need the feature, but we're not
	 * settled on how to indicate signedness of inputs.
	 */
	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.PARAMETER)
	@Experimental
	public @interface OpInput {
		boolean DEFAULT_SIGNED = false;
		int DEFAULT_SLACK = 0;

		/**
		 * Indicates the signedness of the input
		 * 
		 * @see PcodeUseropLibrary.PcodeUseropDefinition#isInSigned(int)
		 */
		boolean signed() default DEFAULT_SIGNED;

		/**
		 * For parameters taking {@code int[]}, usually in a JIT-accelerated emulator, the number of
		 * slack elements to add.
		 * <p>
		 * {@code int[]} values have the elements in little-endian order. That is, the
		 * less-significant legs are in the lower indices. Slack legs are added at the
		 * most-significant end, i.e., at the upper indices. This is useful for algorithms that
		 * benefit from such extension.
		 * 
		 * @return the number of slack elements
		 */
		int slack() default DEFAULT_SLACK;
	}

	/**
	 * An annotation to receive the CALLOTHER p-code op into a parameter
	 * <p>
	 * The annotated parameter must have type {@link PcodeOp}.
	 */
	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.PARAMETER)
	public @interface OpOp {
	}

	/**
	 * Default constructor, usually invoked implicitly
	 */
	public AnnotatedPcodeUseropLibrary() {
		Lookup lookup = getMethodLookup();
		Type opType = getOperandType();
		@SuppressWarnings({ "unchecked", "rawtypes" })
		Class<? extends AnnotatedPcodeUseropLibrary<T>> cls = (Class) this.getClass();
		Set<Method> methods;
		synchronized (CACHE_BY_CLASS) {
			methods = CACHE_BY_CLASS.computeIfAbsent(cls, _ -> collectDefinitions(cls));
		}
		for (Method m : methods) {
			ops.put(m.getName(), AnnotatedPcodeUseropDefinition
					.create(m.getAnnotation(PcodeUserop.class), this, opType, lookup, m));
		}
	}

	/**
	 * Determine the operand type by examining the type substituted for {@code T}
	 * 
	 * @return the type of data processed by the userop
	 */
	protected Type getOperandType() {
		return PcodeUseropLibrary.getOperandType(getClass());
	}

	/**
	 * An override to provide method access, if any non-public method is exported as a userop.
	 * 
	 * @return a lookup that can access all {@link PcodeUserop}-annotated methods.
	 */
	protected Lookup getMethodLookup() {
		return MethodHandles.lookup();
	}
}
