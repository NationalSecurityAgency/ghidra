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
 * Factory class for a {@link JavaProperty}
 */
class JavaPropertyFactory {

	private JavaPropertyFactory() {
	}

	static JavaProperty<?> getProperty(String field, MethodHandle getter, MethodHandle setter) {
		Class<?> cls =
			getter != null ? getter.type().returnType() : setter.type().lastParameterType();
		if (!cls.isPrimitive()) {
			return new ObjectJavaProperty(field, getter, setter);
		}
		if (cls == Boolean.TYPE) {
			return new BooleanJavaProperty(field, getter, setter);
		}
		if (cls == Byte.TYPE) {
			return new ByteJavaProperty(field, getter, setter);
		}
		if (cls == Character.TYPE) {
			return new CharacterJavaProperty(field, getter, setter);
		}
		if (cls == Double.TYPE) {
			return new DoubleJavaProperty(field, getter, setter);
		}
		if (cls == Float.TYPE) {
			return new FloatJavaProperty(field, getter, setter);
		}
		if (cls == Integer.TYPE) {
			return new IntegerJavaProperty(field, getter, setter);
		}
		if (cls == Long.TYPE) {
			return new LongJavaProperty(field, getter, setter);
		}
		if (cls == Short.TYPE) {
			return new ShortJavaProperty(field, getter, setter);
		}
		// it's better than nothing at all
		// users will just need to be extra careful about casting to whatever the new primitive
		// type is when using a getter/setter
		return new ObjectJavaProperty(field, getter, setter);
	}
}
