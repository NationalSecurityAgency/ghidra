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
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.util.Msg;

/**
 * Utility class for working with classes to obtain and create Python properties.
 * 
 * This class is for <b>internal use only</b> and is only public so it can be
 * reached from Python.
 */
public class PropertyUtils {

	private PropertyUtils() {
	}

	/**
	 * Gets the boxed class for a primitive type
	 * 
	 * @param cls the primitive class type
	 * @return the boxed class for a primitive type or the original class if not a primitive type
	 */
	static Class<?> boxPrimitive(Class<?> cls) {
		if (!cls.isPrimitive()) {
			return cls;
		}
		// sure there are cleaner ways to do this
		// you could do a switch over the first character from Class.descriptorString
		// however, for a primitive class, descriptorString goes through exactly this
		// just to produce the descriptor string so there is really no point
		if (cls == Boolean.TYPE) {
			return Boolean.class;
		}
		if (cls == Byte.TYPE) {
			return Byte.class;
		}
		if (cls == Character.TYPE) {
			return Character.class;
		}
		if (cls == Double.TYPE) {
			return Double.class;
		}
		if (cls == Float.TYPE) {
			return Float.class;
		}
		if (cls == Integer.TYPE) {
			return Integer.class;
		}
		if (cls == Long.TYPE) {
			return Long.class;
		}
		if (cls == Short.TYPE) {
			return Short.class;
		}
		// this allows us to still give a functional property
		// if a new primitive type is ever added it can still work
		return cls;
	}

	/**
	 * Gets an array of {@link JavaProperty} for the provided class.
	 * 
	 * This method is for <b>internal use only</b> and is only public
	 * so it can be called from Python.
	 * 
	 * @param cls the class to get the properties for
	 * @return an array of properties
	 */
	public static JavaProperty<?>[] getProperties(Class<?> cls) {
		if (cls == Object.class) {
			return new JavaProperty[0];
		}
		try {
			return doGetProperties(cls);
		}
		catch (Throwable t) {
			Msg.error(PropertyUtils.class,
				"Failed to extract properties for " + cls.getSimpleName(), t);
			return new JavaProperty<?>[0];
		}
	}

	private static JavaProperty<?>[] doGetProperties(Class<?> cls) throws Throwable {
		PropertyPairFactory factory;
		try {
			factory = new PropertyPairFactory(cls);
		}
		catch (IllegalArgumentException e) {
			// skip illegal lookup class
			return new JavaProperty<?>[0];
		}
		return getMethods(cls)
				.filter(PropertyUtils::methodFilter)
				.map(PropertyUtils::toProperty)
				.collect(Collectors.groupingBy(PartialProperty::getName))
				.values()
				.stream()
				.map(factory::merge)
				.flatMap(Optional::stream)
				.toArray(JavaProperty<?>[]::new);
	}

	private static Stream<Method> getMethods(Class<?> cls) {
		// customizations added using JClass._customize are inherited
		// therfore we only care about the ones declared by this class
		return Arrays.stream(cls.getDeclaredMethods())
				.filter(PropertyUtils::methodFilter);
	}

	private static boolean methodFilter(Method m) {
		/*
		This is much simpler than it looks.
		
		A method is considered a getter/setter if it meets the following:

		1. Has public visibility and is not static.
		2. Has a name starting with lowercase get/set/is with the character after
		   the prefix being uppercase.
		3. A getter has 0 parameters and a non-void return type.
		   A setter has 1 parameter and must not return anything.
		   An is getter must return a boolean or Boolean.
		4. The method name must be longer than the prefix.

		The first few checks are done to short circuit and return false sooner rather than later.
		*/
		 
		if (!isPublic(m)) {
			return false;
		}

		int paramCount = m.getParameterCount();
		if (paramCount > 1) {
			return false;
		}

		Class<?> resultType = m.getReturnType();
		String name = m.getName();
		int nameLength = name.length();
		if (nameLength < 3) {
			return false;
		}
		switch (name.charAt(0)) {
			case 'g':
				if (paramCount == 0 && resultType != Void.TYPE) {
					if (nameLength > 3 && name.startsWith("get")) {
						return Character.isUpperCase(name.charAt(3));
					}
				}
				return false;
			case 'i':
				if (paramCount == 0 &&
					(resultType == Boolean.TYPE || resultType == Boolean.class)) {
					if (nameLength > 2 && name.startsWith("is")) {
						return Character.isUpperCase(name.charAt(2));
					}
				}
				return false;
			case 's':
				if (paramCount == 1 && resultType == Void.TYPE) {
					if (nameLength > 3 && name.startsWith("set")) {
						return Character.isUpperCase(name.charAt(3));
					}
				}
				return false;
			default:
				return false;
		}
	}

	private static boolean isPublic(Method m) {
		int mod = m.getModifiers();
		return Modifier.isPublic(mod) && !Modifier.isStatic(mod);
	}

	/**
	 * Helper class for merging methods and removing a layer of reflection
	 */
	private static class PropertyPairFactory {
		private final Lookup lookup;

		private PropertyPairFactory(Class<?> c) {
			lookup = MethodHandles.publicLookup();
		}

		private Optional<JavaProperty<?>> merge(List<PartialProperty> pairs) {
			try {
				if (pairs.size() == 1) {
					PartialProperty p = pairs.get(0);
					MethodHandle h = lookup.unreflect(p.m);
					JavaProperty<?> res =
						p.isGetter() ? JavaPropertyFactory.getProperty(p.name, h, null)
								: JavaPropertyFactory.getProperty(p.name, null, h);
					return Optional.of(res);
				}
				PartialProperty g = pairs.stream()
						.filter(PartialProperty::isGetter)
						.findFirst()
						.orElse(null);
				if (g != null) {
					// go through all remaining methods and take the first matching pair
					// it does not matter if one is a boxed primitive and the other is
					// unboxed because the JavaProperty will use the primitive type anyway
					Class<?> target = boxPrimitive(g.m.getReturnType());
					PartialProperty s = pairs.stream()
							.filter(PartialProperty::isSetter)
							.filter(p -> boxPrimitive(p.m.getParameterTypes()[0]) == target)
							.findFirst()
							.orElse(null);
					MethodHandle gh = lookup.unreflect(g.m);
					MethodHandle sh = s != null ? lookup.unreflect(s.m) : null;
					return Optional.of(JavaPropertyFactory.getProperty(g.name, gh, sh));
				}
			}
			catch (IllegalAccessException e) {
				// this is a class in java.lang.invoke or java.lang.reflect
				// the JVM doesn't allow the creation of handles for these
			}
			return Optional.empty();
		}
	}

	private static PartialProperty toProperty(Method m) {
		// all non properties have already been filtered out
		String name = m.getName();
		if (name.charAt(0) == 'i') {
			name = name.substring(2);
		}
		else {
			name = name.substring(3);
		}
		name = Character.toLowerCase(name.charAt(0)) + name.substring(1);
		return new PartialProperty(m, name);
	}

	/**
	 * Helper class for combining the methods into a property
	 */
	private static class PartialProperty {
		private final Method m;
		private final String name;

		private PartialProperty(Method m, String name) {
			this.m = m;
			this.name = name;
		}

		public boolean isGetter() {
			return m.getParameterCount() == 0 && m.getReturnType() != Void.TYPE;
		}

		public boolean isSetter() {
			return m.getParameterCount() == 1 && m.getReturnType() == Void.TYPE;
		}

		public String getName() {
			return name;
		}
	}
}
