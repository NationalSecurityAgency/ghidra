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
package ghidra.dbg;

import java.lang.annotation.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.*;

import ghidra.dbg.target.TargetObject;
import ghidra.util.Msg;

public abstract class AnnotatedDebuggerAttributeListener implements DebuggerModelListener {
	private static final String ATTR_METHODS =
		"@" + AttributeCallback.class.getSimpleName() + "-annotated methods";
	private static final String PARAMS_ERR =
		ATTR_METHODS + " must accept 2 parameters: (TargetObject, T)";

	@Target(ElementType.METHOD)
	@Retention(RetentionPolicy.RUNTIME)
	protected @interface AttributeCallback {
		String value();
	}

	private static class Wiring {
		private final Map<String, Set<MethodHandle>> handles = new HashMap<>();

		private Wiring(Class<?> cls, Lookup lookup) {
			try {
				collect(cls, lookup);
			}
			catch (IllegalAccessException e) {
				throw new IllegalArgumentException("Lookup must have access " + ATTR_METHODS, e);
			}
		}

		private void collectFromClass(Class<?> cls, Lookup lookup) throws IllegalAccessException {
			for (Method m : cls.getDeclaredMethods()) {
				AttributeCallback annot = m.getAnnotation(AttributeCallback.class);
				if (annot == null) {
					continue;
				}
				Parameter[] parameters = m.getParameters();
				if (parameters.length != 2) {
					throw new IllegalArgumentException(PARAMS_ERR);
				}
				if (!parameters[0].getType().isAssignableFrom(TargetObject.class)) {
					throw new IllegalArgumentException(PARAMS_ERR);
				}
				MethodHandle handle = lookup.unreflect(m);
				handles.computeIfAbsent(annot.value(), __ -> new HashSet<>()).add(handle);
			}
		}

		private void collect(Class<?> cls, Lookup lookup) throws IllegalAccessException {
			collectFromClass(cls, lookup);

			Class<?> s = cls.getSuperclass();
			if (s != null) {
				collect(s, lookup);
			}

			for (Class<?> i : cls.getInterfaces()) {
				collect(i, lookup);
			}
		}

		private void fireChange(AnnotatedDebuggerAttributeListener l, TargetObject object,
				String name, Object value) {
			Set<MethodHandle> set = handles.get(name);
			if (set == null) {
				return;
			}
			for (MethodHandle h : set) {
				try {
					h.invoke(l, object, value);
				}
				catch (Throwable e) {
					Msg.error(this, "Error invoking " + h + ": " + e);
				}
			}
		}
	}

	private static final Map<Class<? extends AnnotatedDebuggerAttributeListener>, Wiring> WIRINGS_BY_CLASS =
		new HashMap<>();

	private final Wiring wiring;

	public AnnotatedDebuggerAttributeListener(Lookup lookup) {
		wiring = WIRINGS_BY_CLASS.computeIfAbsent(getClass(), cls -> new Wiring(cls, lookup));
	}

	protected boolean checkFire(TargetObject object) {
		return true;
	}

	@Override
	public void attributesChanged(TargetObject object, Collection<String> removed,
			Map<String, ?> added) {
		if (!checkFire(object)) {
			return;
		}
		for (String name : removed) {
			wiring.fireChange(this, object, name, null);
		}
		for (Map.Entry<String, ?> ent : added.entrySet()) {
			wiring.fireChange(this, object, ent.getKey(), ent.getValue());
		}
	}
}
