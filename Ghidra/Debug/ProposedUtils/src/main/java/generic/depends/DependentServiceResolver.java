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
package generic.depends;

import java.lang.reflect.*;
import java.util.*;

import generic.depends.err.*;

public class DependentServiceResolver<T> {
	private static final Map<Class<?>, DependentServiceResolver<?>> CACHED = new HashMap<>();

	@SuppressWarnings("unchecked")
	public static <T> DependentServiceResolver<T> get(Class<T> cls)
			throws UnsatisfiedParameterException, UnsatisfiedFieldsException {
		DependentServiceResolver<T> resolver = (DependentServiceResolver<T>) CACHED.get(cls);
		if (resolver == null) {
			CACHED.put(cls, resolver = new DependentServiceResolver<>(cls));
		}
		return resolver;
	}

	@SuppressWarnings("unchecked")
	public static <T> void inject(T t) throws ServiceConstructionException,
			UnsatisfiedParameterException, UnsatisfiedFieldsException {
		get((Class<T>) t.getClass()).injectServices(t);
	}

	private final Set<Class<?>> classesIncluded = new HashSet<>();
	private final Map<Class<?>, Set<Field>> fieldsByClass = new HashMap<>();
	private final Map<Class<?>, Set<Class<?>>> depsByDependents = new HashMap<>();
	private final Map<Class<?>, Method> constructors = new HashMap<>();
	private final List<DependentServiceConstructor<?>> ordered = new ArrayList<>();

	private DependentServiceResolver(Class<T> cls)
			throws UnsatisfiedParameterException, UnsatisfiedFieldsException {
		addClass(cls);
		compile();
	}

	private void addClass(Class<?> cls) {
		if (classesIncluded.contains(cls)) {
			return;
		}
		Class<?> superCls = cls.getSuperclass();
		if (superCls == null) {
			return;
		}
		addClass(superCls);
		for (Class<?> superIf : cls.getInterfaces()) {
			addClass(superIf);
		}

		for (Method m : cls.getDeclaredMethods()) {
			DependentService annot = m.getAnnotation(DependentService.class);
			if (annot == null) {
				continue;
			}

			int mods = m.getModifiers();
			if (Modifier.isStatic(mods)) {
				throw new IllegalArgumentException("Constructor must be a non-static method");
			}

			Class<?> override = annot.override();
			Class<?> rCls = m.getReturnType();
			if (override != DependentService.Sentinel.class) {
				if (!override.isAssignableFrom(rCls)) {
					throw new IllegalArgumentException(
						"Overridden constructor must return same or subclass of original");
				}
				depsByDependents.computeIfAbsent(override, o -> new HashSet<>()).add(rCls);
				constructors.put(override, m);
			}
			constructors.put(rCls, m);
			m.setAccessible(true);

			for (Class<?> pType : m.getParameterTypes()) {
				depsByDependents.computeIfAbsent(rCls, c -> new HashSet<>()).add(pType);
			}
		}
		for (Field f : cls.getDeclaredFields()) {
			DependentService annot = f.getAnnotation(DependentService.class);
			if (annot == null) {
				continue;
			}
			Class<?> fCls = f.getType();
			fieldsByClass.computeIfAbsent(fCls, c -> new HashSet<>()).add(f);
			f.setAccessible(true);
		}
	}

	private void compile() throws UnsatisfiedParameterException, UnsatisfiedFieldsException {
		Set<Class<?>> missing = new HashSet<>(fieldsByClass.keySet());
		missing.removeAll(constructors.keySet());
		if (!missing.isEmpty()) {
			throw new UnsatisfiedFieldsException(missing);
		}
		Set<Class<?>> unordered = new HashSet<>(constructors.keySet());
		while (!unordered.isEmpty()) {
			Set<Class<?>> forRound = new HashSet<>(unordered);
			forRound.removeAll(depsByDependents.keySet());
			if (forRound.isEmpty()) {
				throw new UnsatisfiedParameterException(unordered);
			}
			for (Class<?> ready : forRound) {
				Method m = constructors.get(ready);
				unordered.remove(ready);
				ordered.add(new DependentServiceConstructor<>(ready, m));
				for (Iterator<Set<Class<?>>> iterator =
					depsByDependents.values().iterator(); iterator.hasNext();) {
					Set<Class<?>> deps = iterator.next();
					deps.remove(ready);
					if (deps.isEmpty()) {
						iterator.remove();
					}
				}
			}
		}
		assert ordered.size() == constructors.size();
	}

	public void injectServices(T obj) throws ServiceConstructionException {
		Map<Class<?>, Object> instancesByClass = new HashMap<>();
		Map<Method, Object> constructed = new HashMap<>();
		Map<Class<?>, Set<Field>> fieldsByClass = new HashMap<>(this.fieldsByClass);
		for (DependentServiceConstructor<?> cons : ordered) {
			Object service = constructed.get(cons.method);
			if (service == null) {
				service = cons.construct(obj, instancesByClass);
				constructed.put(cons.method, service);
			}
			instancesByClass.put(cons.cls, service);
			Set<Field> fields = fieldsByClass.remove(cons.cls);
			if (fields != null) {
				for (Field f : fields) {
					try {
						f.set(obj, service);
					}
					catch (IllegalArgumentException | IllegalAccessException e) {
						throw new AssertionError(e);
					}
				}
			}
		}
		if (!fieldsByClass.isEmpty()) {
			throw new ServiceConstructionException(
				"No service constructor for " + fieldsByClass.keySet(), null);
		}
	}
}
