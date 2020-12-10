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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;

import generic.depends.err.ServiceConstructionException;

class DependentServiceConstructor<T> {
	final Class<T> cls;
	final Method method;

	DependentServiceConstructor(Class<T> cls, Method method) {
		if (!cls.isAssignableFrom(method.getReturnType())) {
			throw new IllegalArgumentException(
				"Constructor method must return type assignable to the class");
		}
		this.cls = cls;
		this.method = method;
	}

	@SuppressWarnings("unchecked")
	T construct(Object obj, Map<Class<?>, Object> dependencies)
			throws ServiceConstructionException {
		List<Object> params = new ArrayList<>(method.getParameterCount());
		for (Class<?> pType : method.getParameterTypes()) {
			Object p = dependencies.get(pType);
			assert p != null;
			params.add(p);
		}
		try {
			return (T) method.invoke(obj, params.toArray());
		}
		catch (InvocationTargetException e) {
			throw new ServiceConstructionException(
				"Error constructing dependent service via " + method, e.getCause());
		}
		catch (IllegalAccessException | IllegalArgumentException e) {
			throw new AssertionError(e);
		}
	}
}
