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
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;

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

	class AnnotatedSleighUseropDefinition implements SleighUseropDefinition<T> {
		private final Method method;

		public AnnotatedSleighUseropDefinition(Method method) {
			this.method = method;

			for (Class<?> ptype : method.getParameterTypes()) {
				if (Varnode.class.isAssignableFrom(ptype)) {
					continue;
				}
				if (getOperandType().isAssignableFrom(ptype)) {
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
		public void execute(PcodeExecutorStatePiece<T, T> state, Varnode outVar, List<Varnode> inVars) {
			// outVar is ignored
			Object[] args = new Object[inVars.size()];
			Class<?>[] ptypes = method.getParameterTypes();
			for (int i = 0; i < args.length; i++) {
				if (Varnode.class.isAssignableFrom(ptypes[i])) {
					args[i] = inVars.get(i);
				}
				else {
					args[i] = state.getVar(inVars.get(i));
				}
			}
			try {
				method.invoke(AnnotatedSleighUseropLibrary.this, args);
			}
			catch (IllegalAccessException | IllegalArgumentException
					| InvocationTargetException e) {
				throw new AssertionError(e);
			}
		}
	}

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.METHOD)
	@interface SleighUserop {
	}

	Map<String, SleighUseropDefinition<T>> ops = new HashMap<>();

	public AnnotatedSleighUseropLibrary() {
		@SuppressWarnings({ "unchecked", "rawtypes" })
		Class<? extends AnnotatedSleighUseropLibrary<T>> cls = (Class) this.getClass();
		Set<Method> methods = CACHE_BY_CLASS.computeIfAbsent(cls, __ -> collectDefinitions(cls));
		for (Method m : methods) {
			ops.put(m.getName(), new AnnotatedSleighUseropDefinition(m));
		}
	}

	protected abstract Class<T> getOperandType();

	@Override
	public Map<String, SleighUseropDefinition<T>> getUserops() {
		return ops;
	}
}
