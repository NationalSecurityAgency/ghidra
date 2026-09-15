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
package ghidra.pcode.emu.jit;

import java.lang.classfile.ClassBuilder;
import java.lang.constant.ClassDesc;
import java.lang.reflect.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.lang3.reflect.TypeLiteral;

/**
 * Some utilities for generating type signatures, suitable for use with
 * {@link ClassBuilder#withField(String, ClassDesc, int)}.
 * <p>
 * <b>WARNING:</b> The internal representation of type signatures is defined by the JVM
 * specification. While the standard Class-File API handles most descriptor generation, these
 * utilities produce <em>generic</em> signatures (as in the {@code Signature} attribute), which
 * still require manual construction.
 */
public enum JitJvmTypeUtils {
	;

	/**
	 * Get the internal name of a class (e.g., {@code java.lang.String}).
	 *
	 * @param cls the class
	 * @return the internal name
	 */
	public static String classToInternalName(Class<?> cls) {
		return cls.getName().replace('.', '/');
	}

	/**
	 * Presume the given type is a {@link Class} and get its internal name
	 * 
	 * @param type the type
	 * @return the internal name
	 */
	public static String rawToInternalName(Type type) {
		return classToInternalName((Class<?>) type);
	}

	/**
	 * Get the signature of the given wildcard type
	 * <ul>
	 * <li>{@code sig(?) = *}</li>
	 * <li>{@code sig(? super MyType) = -sig(MyType)}</li>
	 * <li>{@code sig(? extends MyType) = +sig(MyType)}</li>
	 * </ul>
	 * 
	 * @param wt the type
	 * @return the signature
	 */
	public static String wildToSignature(WildcardType wt) {
		Type lower = wt.getLowerBounds().length == 0 ? null : wt.getLowerBounds()[0];
		Type upper = wt.getUpperBounds()[0];
		if (lower == null && upper == Object.class) {
			return "*";
		}
		if (lower == null) {
			return "+" + typeToSignature(upper);
		}
		if (upper == Object.class) {
			return "-" + typeToSignature(lower);
		}
		throw new UnsupportedOperationException();
	}

	/**
	 * Get the signature of the given type
	 * <p>
	 * For the use case this supports, probably the best way to obtain a {@link Type} is via
	 * {@link TypeLiteral}.
	 * <p>
	 * As of the JVM 21, internal type signatures are derived as:
	 * <ul>
	 * <li>{@code sig(my.MyType) = Lmy/MyType.class;}</li>
	 * <li>{@code sig(my.MyType[]) = [sig(my.MyType)}</li>
	 * <li>{@code sig(my.MyType<Yet, Another, ...>) = Lmy/MyType<sig(Yet), sig(Another), ...>;}</li>
	 * <li>Wildcard types as in {@link #wildToSignature(WildcardType)}</li>
	 * <li>Type variables are not supported by these utilities</li>
	 * </ul>
	 * 
	 * @param type the type
	 * @return the signature
	 */
	public static String typeToSignature(Type type) {
		return switch (type) {
			case Class<?> cls -> "L" + classToInternalName(cls) + ";";
			case GenericArrayType arr -> "[" + typeToSignature(arr.getGenericComponentType());
			case ParameterizedType pt -> "L" + rawToInternalName(pt.getRawType()) + "<" +
				Stream.of(pt.getActualTypeArguments())
						.map(a -> typeToSignature(a))
						.collect(Collectors.joining(",")) +
				">;";
			case WildcardType wt -> wildToSignature(wt);
			default -> throw new UnsupportedOperationException();
		};
	}

	/**
	 * Compute the erasure of a type variable with the given upper bounds
	 * 
	 * @param bounds the upper bounds
	 * @return the erasure
	 */
	public static Class<?> eraseBounds(Type[] bounds) {
		if (bounds.length == 0) {
			return Object.class;
		}
		return erase(bounds[0]);
	}

	/**
	 * Compute the erasure of the given type
	 * <p>
	 * For a class, this is just the same class. For an array, it is the array of the erasure of the
	 * element type. For a parameterized type, we take the erasure of the raw type, which should in
	 * turn be a class. For a wildcard, we take the erasure of its first upper bound.
	 * 
	 * @param type the type
	 * @return the erasure
	 */
	public static Class<?> erase(Type type) {
		return switch (type) {
			case Class<?> cls -> cls;
			case GenericArrayType arr -> Array.newInstance(erase(arr.getGenericComponentType()), 0)
					.getClass();
			case ParameterizedType pt -> erase(pt.getRawType());
			case TypeVariable<?> tv -> eraseBounds(tv.getBounds());
			case WildcardType wt -> eraseBounds(wt.getUpperBounds());
			default -> throw new UnsupportedOperationException();
		};
	}
}
