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
package utilities.util;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.*;
import java.util.Arrays;
import java.util.List;

public enum ProxyUtilities {
	;

	/**
	 * Check if two methods are the same, ignoring the declaring class.
	 * 
	 * This returns true if all the following are met: 1) They have the same name, 2) They have the
	 * same return type, and 3) They have the same parameter types.
	 * 
	 * @param m1 the first method
	 * @param m2 the second method
	 * @return true if they are the same, false otherwise;
	 */
	public static boolean areSameMethod(Method m1, Method m2) {
		if (!m1.getName().equals(m2.getName())) {
			// NOTE: Could be faster using ==, as does Method#equals(Method)
			return false;
		}
		if (!m1.getReturnType().equals(m2.getReturnType())) {
			// NOTE: Method#equals(Method) does NOT use == for this
			return false;
		}
		if (!Arrays.equals(m1.getParameterTypes(), m2.getParameterTypes())) {
			return false;
		}
		return true;
	}

	public static MethodHandle getSuperMethodHandle(Method method) throws IllegalAccessException {
		return getSuperMethodHandle(method, MethodHandles.lookup());
	}

	public static MethodHandle getSuperMethodHandle(Method method, MethodHandles.Lookup lookup)
			throws IllegalAccessException {
		Class<?> dCls = method.getDeclaringClass();
		return MethodHandles.privateLookupIn(dCls, lookup).unreflectSpecial(method, dCls);
	}

	/**
	 * Mix-in interfaces with default methods atop the given delegate.
	 * 
	 * Where both the delegate and a mixin provide an implementation, the delegate's is preferred.
	 * 
	 * @param <T> the delegate's and proxy's type
	 * @param <U> a super interface common to all mixins
	 * @param iface an interface of the delegate that also defines the proxy's type
	 * @param delegate the delegate, providing implementations of all abstract methods
	 * @param mixins the mixins
	 * @param lookup a lookup which has access to the interfaces and their methods
	 */
	@SuppressWarnings("unchecked")
	public static <T, U> T composeOnDelegate(Class<T> iface, T delegate,
			List<Class<? extends U>> mixins, MethodHandles.Lookup lookup) {
		Class<?>[] allIface = new Class<?>[1 + mixins.size()];
		allIface = mixins.toArray(allIface);
		allIface[allIface.length - 1] = iface;
		ComposedHandler handler = new ComposedHandler(delegate, lookup);
		return (T) Proxy.newProxyInstance(delegate.getClass().getClassLoader(), allIface, handler);
	}

	private static class ComposedHandler implements InvocationHandler {
		private final Object delegate;
		private final MethodHandles.Lookup lookup;

		ComposedHandler(Object delegate, MethodHandles.Lookup lookup) {
			this.delegate = delegate;
			this.lookup = lookup;
		}

		@Override
		public Object invoke(Object proxy, Method method, Object[] args)
				throws Throwable {
			// TODO: Cache handles or pre-load them
			Object result;
			if (method.getDeclaringClass().isAssignableFrom(delegate.getClass())) {
				MethodHandle handle = lookup.unreflect(method);
				result = handle.bindTo(delegate).invokeWithArguments(args);
			}
			else if (!method.isDefault()) {
				throw new IllegalStateException(
					"Delegate must implement abstract methods from all mixins. Missed: " + method);
			}
			else {
				MethodHandle mh = getSuperMethodHandle(method, lookup);
				result = mh.bindTo(proxy).invokeWithArguments(args);
			}
			/**
			 * NOTE: I cannot replace the delegate with the proxy here (say, to prevent accidental
			 * leakage) for at least two reasons. 1) I may want direct access to the delegate. 2) It
			 * wouldn't work when the return value itself wraps or will provide the delegate (e.g.,
			 * a future).
			 */
			return result;
		}
	}
}
