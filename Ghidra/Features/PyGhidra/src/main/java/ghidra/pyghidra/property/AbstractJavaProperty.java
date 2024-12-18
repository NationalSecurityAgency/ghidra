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
package ghidra.pyghidra.property;

import java.lang.invoke.MethodHandle;

/**
 * Abstract base class for implementing a {@link JavaProperty}.
 *
 * This class provides the fset implementation as well as all helpers so
 * that each child class only needs to define a constructor and a fget
 * method returning the correct primitive type. Each child class can
 * implement fget as follows:
 *
 * {@snippet lang="java" :
 * public type fget(Object self) throws Throwable { // @highlight substring="type"
 *     return doGet(self);
 * }
 * }
 *
 * The PyGhidra internals expects every {@link JavaProperty} to be an instance of this class.
 * No checking is required or performed since the {@link JavaProperty} interface and this
 * class are sealed.
 */
abstract sealed class AbstractJavaProperty<T> implements JavaProperty<T> permits
		BooleanJavaProperty, ByteJavaProperty, CharacterJavaProperty,
		DoubleJavaProperty, FloatJavaProperty, IntegerJavaProperty,
		LongJavaProperty, ObjectJavaProperty, ShortJavaProperty {

	/**
	 * The name of the property
	 */
	public final String field;

	// The handles to the underlying get/set methods
	private final MethodHandle getter;
	private final MethodHandle setter;

	protected AbstractJavaProperty(String field, MethodHandle getter, MethodHandle setter) {
		this.field = field;
		this.getter = getter;
		this.setter = setter;
	}

	/**
	 * Checks if this property has a getter
	 *
	 * @return true if this property has a getter
	 */
	public boolean hasGetter() {
		return getter != null;
	}

	/**
	 * Checks if this property has a setter
	 *
	 * @return true if this property has a setter
	 */
	public boolean hasSetter() {
		return setter != null;
	}

	// this is only for testing
	boolean hasValidSetter() {
		if (setter == null) {
			return false;
		}
		if (getter == null) {
			return true;
		}
		Class<?> getterType = PropertyUtils.boxPrimitive(getter.type().returnType());
		// for a MethodType the parameter we want is at index 1
		Class<?> setterType = PropertyUtils.boxPrimitive(setter.type().parameterType(1));
		return getterType == setterType;
	}

	protected final T doGet(Object self) throws Throwable {
		return (T) getter.invoke(self);
	}

	@Override
	public final void fset(Object self, T value) throws Throwable {
		setter.invoke(self, value);
	}
}
