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
package ghidra.app.util.bin.format.golang.structmapping;

import java.util.*;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.*;
import java.lang.reflect.Array;

import ghidra.program.model.data.*;

public class ReflectionHelper {
	private static final Set<Class<?>> NUM_CLASSES =
		Set.of(Long.class, Long.TYPE, Integer.class, Integer.TYPE, Short.class, Short.TYPE,
			Byte.class, Byte.TYPE, Character.class, Character.TYPE);
	private static final Map<Class<?>, Integer> SIZEOF_NUM_CLASSES =
		Map.ofEntries(
			Map.entry(Long.class, Long.BYTES),
			Map.entry(Long.TYPE, Long.BYTES),
			Map.entry(Integer.class, Integer.BYTES),
			Map.entry(Integer.TYPE, Integer.BYTES),
			Map.entry(Short.class, Short.BYTES),
			Map.entry(Short.TYPE, Short.BYTES),
			Map.entry(Byte.class, Byte.BYTES),
			Map.entry(Byte.TYPE, Byte.BYTES),
			Map.entry(Character.class, Character.BYTES),
			Map.entry(Character.TYPE, Character.BYTES));
	private static final Map<Class<?>, String> DEFAULT_DATATYPE_NAME =
		Map.ofEntries(
			Map.entry(Long.class, "long"),
			Map.entry(Long.TYPE, "long"),
			Map.entry(Integer.class, "int"),
			Map.entry(Integer.TYPE, "int"),
			Map.entry(Short.class, "word"),
			Map.entry(Short.TYPE, "word"),
			Map.entry(Byte.class, "byte"),
			Map.entry(Byte.TYPE, "byte"),
			Map.entry(Character.class, "wchar"),
			Map.entry(Character.TYPE, "wchar"));

	public static boolean isPrimitiveType(Class<?> clazz) {
		return NUM_CLASSES.contains(clazz);
	}

	/**
	 * Write a value to a field in a java class.
	 * 
	 * @param field reflection {@link Field}
	 * @param obj java instance that contains the field 
	 * @param value value to write
	 * @throws IOException
	 */
	public static void assignField(Field field, Object obj, Object value) throws IOException {
		Class<?> fieldType = field.getType();

		try {
			if (fieldType.isPrimitive() && NUM_CLASSES.contains(value.getClass())) {
				field.set(obj, value);
			}
			else {
				if (!fieldType.isInstance(value)) {
					throw new IOException("Bad conversion from %s to %s.%s:%s".formatted(
						value.getClass().getSimpleName(),
						obj.getClass().getSimpleName(),
						field.getName(),
						fieldType.getSimpleName()));
				}
				field.set(obj, value);
			}
		}
		catch (IllegalArgumentException | IllegalAccessException e) {
			throw new IOException(e);
		}
	}

	/**
	 * Return Ghidra data type representing an array of primitive values.
	 * 
	 * @param array_value java array object
	 * @param fieldType
	 * @param length
	 * @param signedness
	 * @param dataTypeMapper
	 * @return
	 */
	public static DataType getArrayOutputDataType(Object array_value, Class<?> fieldType, int length,
			Signedness signedness, DataTypeMapper dataTypeMapper) {
		int arrayLen = array_value != null ? Array.getLength(array_value) : 0;
		Class<?> elementType = fieldType.getComponentType();
		DataType elementDT =
			getPrimitiveOutputDataType(elementType, length, signedness, dataTypeMapper);

		return new ArrayDataType(elementDT, arrayLen, -1, dataTypeMapper.getDTM());
	}

	public static DataType getPrimitiveOutputDataType(Class<?> fieldType, int length,
			Signedness signedness, DataTypeMapper dataTypeMapper) {

		boolean isChar = (fieldType == Character.class || fieldType == Character.TYPE);
		DataTypeManager dtm = dataTypeMapper.getDTM();

		if (length == -1) {
			length = getPrimitiveSizeof(fieldType);
		}
		if (signedness == Signedness.Unspecified) {
			signedness = isChar ? Signedness.Unsigned : Signedness.Signed;
		}

		String defaultDtName = DEFAULT_DATATYPE_NAME.get(fieldType);
		if (isChar && length == 1) {
			defaultDtName = "char";
		}
		DataType dt = dataTypeMapper.getType(defaultDtName, DataType.class);
		if (dt == null && isChar) {
			dt = switch (length) {
				case 1 -> CharDataType.dataType;
				case 2 -> WideChar16DataType.dataType;
				default -> null;
			};
		}

		if (dt == null || !matches(dt, length, signedness)) {
			dt = signedness == Signedness.Signed
					? AbstractIntegerDataType.getSignedDataType(length, dtm)
					: AbstractIntegerDataType.getSignedDataType(length, dtm);
		}
		return dt;
	}

	private static boolean matches(DataType dt, int length, Signedness signedness) {
		return (length == -1 || length == dt.getLength()) &&
			(signedness == Signedness.Unspecified ||
				(dt instanceof AbstractIntegerDataType intDT) &&
					(signedness == Signedness.Signed) == intDT.isSigned());
	}

	public static int getPrimitiveSizeof(Class<?> fieldType) {
		return SIZEOF_NUM_CLASSES.getOrDefault(fieldType, 1);
	}

	public static boolean hasStructureMapping(Class<?> clazz) {
		return clazz.getAnnotation(StructureMapping.class) != null;
	}

	public static Signedness getDataTypeSignedness(DataType dt) {
		if (dt instanceof TypeDef typedefDT) {
			dt = typedefDT.getBaseDataType();
		}
		if (dt instanceof AbstractIntegerDataType intDT) {
			return intDT.isSigned() ? Signedness.Signed : Signedness.Unsigned;
		}
		return Signedness.Signed; // default
	}

	public static Method getCommentMethod(Class<?> clazz, String commentGetterName,
			String defaultGetterName) {
		if (commentGetterName.isBlank()) {
			commentGetterName = defaultGetterName;
		}
		Method commentGetter = ReflectionHelper.requireGetter(clazz, commentGetterName);
		if (commentGetter == null) {
			throw new IllegalArgumentException(
				"Missing getter %s for %s".formatted(commentGetterName, clazz));
		}
		return commentGetter;
	}

	public static Method requireGetter(Class<?> clazz, String getterName) {
		Method method = findGetter(clazz, getterName);
		if (method == null) {
			throw new IllegalArgumentException(
				"Missing getter %s for %s".formatted(getterName, clazz));
		}
		return method;
	}

	public static Method findGetter(Class<?> structClass, String getterName) {
		Method getter = getMethod(structClass, getterName);
		if (getter == null) {
			String getGetterName = "get%s%s".formatted(getterName.substring(0, 1).toUpperCase(),
				getterName.substring(1));
			getter = getMethod(structClass, getGetterName);
		}
		return getter;
	}

	public static <T> Constructor<T> getCtor(Class<T> clazz, Class<?>... paramTypes) {
		try {
			return clazz.getDeclaredConstructor(paramTypes);
		}
		catch (NoSuchMethodException | SecurityException e) {
			// fail
		}
		return null;
	}

	static Method getMethod(Class<?> clazz, String methodName, Class<?>... paramTypes) {
		try {
			// try both public and private methods in the class
			return clazz.getDeclaredMethod(methodName, paramTypes);
		}
		catch (NoSuchMethodException | SecurityException e) {
			// fail, next try inherited public methods
		}
		try {
			return clazz.getMethod(methodName, paramTypes);
		}
		catch (NoSuchMethodException | SecurityException e) {
			// fail
		}
		return null;
	}

	public static void invokeMethods(List<Method> methods, Object obj, Object... params)
			throws IOException {
		for (Method method : methods) {
			try {
				method.invoke(obj, params);
			}
			catch (IllegalAccessException | InvocationTargetException e) {
				throw new IOException(e);
			}
		}

	}

	public static <T, CTX> T createInstance(Class<T> targetClass, CTX optionalContext)
			throws IllegalArgumentException {

		try {
			if (optionalContext != null) {
				Constructor<T> ctor = getCtor(targetClass, optionalContext.getClass());
				if (ctor != null) {
					ctor.setAccessible(true);
					return ctor.newInstance(optionalContext);
				}
			}
			Constructor<T> ctor = getCtor(targetClass);
			if (ctor != null) {
				ctor.setAccessible(true);
				return ctor.newInstance();
			}
			throw new IllegalArgumentException("Missing ctor for " + targetClass.getSimpleName());
		}
		catch (SecurityException | InstantiationException | IllegalAccessException
				| InvocationTargetException e) {
			throw new IllegalArgumentException(e);
		}
	}

	public static <T> T callCtor(Constructor<T> ctor, Object... params)
			throws IllegalArgumentException {
		try {
			return ctor.newInstance(params);
		}
		catch (SecurityException | InstantiationException | IllegalAccessException
				| InvocationTargetException e) {
			throw new IllegalArgumentException(e);
		}
	}

	public static <T> Object callGetter(Method getterMethod, T obj)
			throws IOException {
		return callGetter(getterMethod, obj, Object.class);
	}

	public static <T, R> R callGetter(Method getterMethod, T obj, Class<R> expectedType)
			throws IOException {
		try {
			Object getterValue = getterMethod.invoke(obj);
			if (getterValue == null || expectedType.isInstance(getterValue)) {
				return expectedType.cast(getterValue);
			}
			return null;
		}
		catch (IllegalAccessException | InvocationTargetException e) {
			throw new IOException(e);
		}
	}

	public static void getMarkedMethods(Class<?> targetClass,
			Class<? extends Annotation> annotationClass, List<Method> methods,
			boolean includeParentClasses, Class<?>... paramClasses) {
		if (includeParentClasses && targetClass.getSuperclass() != null) {
			getMarkedMethods(targetClass.getSuperclass(), annotationClass, methods,
				includeParentClasses, paramClasses);
		}
		methodloop: for (Method method : targetClass.getDeclaredMethods()) {
			if (method.getParameterCount() == paramClasses.length &&
				method.getAnnotation(annotationClass) != null) {
				Class<?>[] parameterTypes = method.getParameterTypes();
				if (parameterTypes.length != paramClasses.length) {
					continue;
				}
				for (int i = 0; i < parameterTypes.length; i++) {
					Class<?> methodParamClass = parameterTypes[i];
					if (!methodParamClass.isAssignableFrom(paramClasses[i])) {
						continue methodloop;
					}
				}
				method.setAccessible(true);
				methods.add(method);
			}
		}
	}

	public static <T extends Annotation> List<T> getAnnotations(Class<?> targetClass,
			Class<T> annotationClass, List<T> result) {
		if (result == null) {
			result = new ArrayList<>();
		}
		T annotation = targetClass.getAnnotation(annotationClass);
		if (annotation != null) {
			result.add(annotation);
		}
		if (targetClass.getSuperclass() != null) {
			getAnnotations(targetClass.getSuperclass(), annotationClass, result);
		}
		return result;
	}

	public static <R> R getFieldValue(Object obj, Field field, Class<R> expectedType)
			throws IOException {
		try {
			Object val = field.get(obj);
			if (val != null && !expectedType.isInstance(val)) {
				throw new IOException(
					"Unexpected field value type: " + val.getClass() + " in " + field);
			}
			return expectedType.cast(val);
		}
		catch (IllegalArgumentException | IllegalAccessException e) {
			throw new IOException(e);
		}
	}

}
