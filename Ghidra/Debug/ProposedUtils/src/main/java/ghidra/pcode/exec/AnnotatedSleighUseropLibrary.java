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
import java.util.*;

import org.apache.commons.lang3.reflect.TypeUtils;

import ghidra.program.model.pcode.Varnode;

public abstract class AnnotatedSleighUseropLibrary<T> implements SleighUseropLibrary<T> {
	private static final Map<Class<?>, Set<Method>> CACHE_BY_CLASS = new HashMap<>();

	private static Set<Method> collectDefinitions(
			Class<? extends AnnotatedSleighUseropLibrary<?>> cls) {
		Set<Method> defs = new HashSet<>();
		collectDefinitions(cls, defs, new HashSet<>());
		return defs;
	}

	private static void collectDefinitions(Class<?> cls, Set<Method> defs, Set<Class<?>> visited) {
		if (!visited.add(cls)) {
			return;
		}
		Class<?> superCls = cls.getSuperclass();
		if (superCls != null) {
			collectDefinitions(superCls, defs, visited);
		}
		for (Class<?> superIf : cls.getInterfaces()) {
			collectDefinitions(superIf, defs, visited);
		}
		collectClassDefinitions(cls, defs);
	}

	private static void collectClassDefinitions(Class<?> cls, Set<Method> defs) {
		for (Method method : cls.getDeclaredMethods()) {
			SleighUserop annot = method.getAnnotation(SleighUserop.class);
			if (annot == null) {
				continue;
			}
			defs.add(method);
		}
	}

	static class AnnotatedSleighUseropDefinition<T> implements SleighUseropDefinition<T> {
		private final Method method;
		private final MethodHandle handle;

		public AnnotatedSleighUseropDefinition(AnnotatedSleighUseropLibrary<T> library,
				Class<T> opType, Lookup lookup, Method method) {
			this.method = method;
			try {
				this.handle = lookup.unreflect(method).bindTo(library);
			}
			catch (IllegalAccessException e) {
				throw new AssertionError("Cannot access " + method + " having @" +
					SleighUserop.class.getSimpleName() + " annotation. Override getMethodLookup()");
			}

			for (Class<?> ptype : method.getParameterTypes()) {
				if (Varnode.class.isAssignableFrom(ptype)) {
					continue;
				}
				if (opType.isAssignableFrom(ptype)) {
					continue;
				}
				throw new IllegalArgumentException(
					"pcode userops can only take Varnode inputs");
			}
		}

		@Override
		public String getName() {
			return method.getName();
		}

		@Override
		public int getOperandCount() {
			return method.getParameterCount();
		}

		@Override
		public void execute(PcodeExecutorStatePiece<T, T> state, Varnode outVar,
				List<Varnode> inVars) {
			// outVar is ignored
			List<Object> args = Arrays.asList(new Object[inVars.size()]);
			Class<?>[] ptypes = method.getParameterTypes();
			for (int i = 0; i < args.size(); i++) {
				if (Varnode.class.isAssignableFrom(ptypes[i])) {
					args.set(i, inVars.get(i));
				}
				else {
					args.set(i, state.getVar(inVars.get(i)));
				}
			}
			try {
				handle.invokeWithArguments(args);
			}
			catch (PcodeExecutionException e) {
				throw e;
			}
			catch (Throwable e) {
				throw new PcodeExecutionException("Error executing userop", null, e);
			}
		}
	}

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.METHOD)
	public @interface SleighUserop {
	}

	Map<String, SleighUseropDefinition<T>> ops = new HashMap<>();

	public AnnotatedSleighUseropLibrary() {
		Lookup lookup = getMethodLookup();
		Class<T> opType = getOperandType();
		@SuppressWarnings({ "unchecked", "rawtypes" })
		Class<? extends AnnotatedSleighUseropLibrary<T>> cls = (Class) this.getClass();
		Set<Method> methods = CACHE_BY_CLASS.computeIfAbsent(cls, __ -> collectDefinitions(cls));
		for (Method m : methods) {
			ops.put(m.getName(), new AnnotatedSleighUseropDefinition<>(this, opType, lookup, m));
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	protected Class<T> getOperandType() {
		Map<TypeVariable<?>, Type> args =
			TypeUtils.getTypeArguments(getClass(), AnnotatedSleighUseropLibrary.class);
		if (args == null) {
			return (Class) Object.class;
		}
		Type type = args.get(AnnotatedSleighUseropLibrary.class.getTypeParameters()[0]);
		if (!(type instanceof Class<?>)) {
			return (Class) Object.class;
		}
		return (Class) type;
	}

	protected Lookup getMethodLookup() {
		return MethodHandles.lookup();
	}

	@Override
	public Map<String, SleighUseropDefinition<T>> getUserops() {
		return ops;
	}
}
