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

import java.lang.reflect.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.lang3.reflect.TypeLiteral;
import org.objectweb.asm.ClassVisitor;

/**
 * Some utilities for generating type signatures, suitable for use with
 * {@link ClassVisitor#visitField(int, String, String, String, Object)}.
 * 
 * <p>
 * <b>WARNING:</b> It seems to me, the internal representation of signatures as accepted by the ASM
 * API is not fixed from version to version. In the future, these utilities may need to be updated
 * to work with multiple versions, if the representation changes in a newer classfile format.
 * Hopefully, the upcoming classfile API will obviate the need for any of this.
 */
public enum JitJvmTypeUtils {
	;

	/**
	 * Get the internal name of a class as in {@link org.objectweb.asm.Type#getInternalName(Class)}.
	 * 
	 * @param cls the class
	 * @return the internal name
	 */
	public static String classToInternalName(Class<?> cls) {
		return org.objectweb.asm.Type.getInternalName(cls);
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
	 * 
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
	 * 
	 * <p>
	 * For the use case this supports, probably the best way to obtain a {@link Type} is via
	 * {@link TypeLiteral}.
	 * 
	 * <p>
	 * As of the JVM 21, internal type signatures are derived as:
	 * 
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
}
