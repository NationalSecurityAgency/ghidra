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
package utilities.util.reflection;

import java.io.*;
import java.lang.reflect.*;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import ghidra.util.exception.AssertException;

public class ReflectionUtilities {

	private static final String JAVA_AWT_PATTERN = "java.awt";
	private static final String JAVA_REFLECT_PATTERN = "java.lang.reflect";
	private static final String JDK_INTERNAL_REFLECT_PATTERN = "jdk.internal.reflect";
	private static final String SWING_JAVA_PATTERN = "java.swing";
	private static final String SWING_JAVAX_PATTERN = "javax.swing";
	private static final String SUN_AWT_PATTERN = "sun.awt";
	private static final String SUN_REFLECT_PATTERN = "sun.reflect";
	private static final String SECURITY_PATTERN = "java.security";

	private static final String JUNIT_PATTERN = ".junit";
	private static final String MOCKIT_PATTERN = "mockit";

	private ReflectionUtilities() {
		// utils class; can't create
	}

	/**
	* Locates the field of the name <code>fieldName</code> on the given 
	* class.  If the given class does not contain the field, then this 
	* method will recursively call up <code>containingClass</code>'s 
	* implementation tree looking for a parent implementation of the 
	* requested field.
	* 
	* @param fieldName The name of the field to locate.
	* @param containingClass The class that contains the desired field.
	* @return The Field object that matches the given name, or null if not
	*         suitable field could be found.
	*/
	public static Field locateStaticFieldObjectOnClass(String fieldName, Class<?> containingClass) {
		Field field = null;

		try {
			field = containingClass.getDeclaredField(fieldName);
		}
		catch (NoSuchFieldException nsfe) {
			// O.K., the field may be located on a parent class.  So, we
			// will call this method on the parent class
			Class<?> parentClass = containingClass.getSuperclass();

			if (parentClass != null) {
				field = locateFieldObjectOnClass(fieldName, parentClass);
			}
		}

		return field;
	}

	/**
	 * Locates the field of the name <code>fieldName</code> on the given 
	 * class.  If the given class does not contain the field, then this 
	 * method will recursively call up <code>containingClass</code>'s 
	 * implementation tree looking for a parent implementation of the 
	 * requested field.
	 * 
	 * @param fieldName The name of the field to locate.
	 * @param containingClass The class that contains the desired field.
	 * @return The Field object that matches the given name, or null if not
	 *         suitable field could be found.
	 */
	public static Field locateFieldObjectOnClass(String fieldName, Class<?> containingClass) {
		Field field = null;

		try {
			field = containingClass.getDeclaredField(fieldName);
		}
		catch (NoSuchFieldException nsfe) {
			// O.K., the field may be located on a parent class.  So, we
			// will call this method on the parent class
			Class<?> parentClass = containingClass.getSuperclass();

			if (parentClass != null) {
				field = locateFieldObjectOnClass(fieldName, parentClass);
			}
		}

		return field;
	}

	/**
	 * Locates the method of the name <code>methodName</code> on the given 
	 * class.  If the given class does not contain the method, then this 
	 * method will recursively call up <code>containingClass</code>'s 
	 * implementation tree looking for a parent implementation of the 
	 * requested method.
	 * 
	 * @param methodName The name of the method to locate.
	 * @param containingClass The class that contains the desired method.
	 * @param parameterTypes The parameters of the desired method (may be null).
	 * @return The Method object that matches the given name, or null if not
	 *         suitable method could be found.
	 */
	public static Method locateMethodObjectOnClass(String methodName, Class<?> containingClass,
			Class<?>[] parameterTypes) {
		Method method = null;

		try {
			// if we get an exception here, then the current class does not
			// declare the method, but its parent may
			method = containingClass.getDeclaredMethod(methodName, parameterTypes);
		}
		catch (NoSuchMethodException nsme) {
			// O.K., the method may be located on a parent class.  So, we
			// will call this method on the parent class
			Class<?> parentClass = containingClass.getSuperclass();

			if (parentClass != null) {
				method = locateMethodObjectOnClass(methodName, parentClass, parameterTypes);
			}
		}

		return method;
	}

	public static Constructor<?> locateConstructorOnClass(Class<?> containingClass,
			Class<?>[] parameterTypes) {

		Constructor<?> constructor = null;

		try {
			constructor = containingClass.getDeclaredConstructor(parameterTypes);
		}
		catch (SecurityException e) {
			// shouldn't happen
		}
		catch (NoSuchMethodException e) {
			// no constructor with the given parameters
		}

		return constructor;
	}

	/**
	 * Get the first field specification contained within containingClass which has the type classType.
	 * This method is only really useful if it is known that only a single field of 
	 * classType exists within the containingClass hierarchy.
	 * @param classType the class
	 * @param containingClass the class that contains a field of the given type
	 * @return field which corresponds to type classType or null
	 */
	public static Field locateFieldByTypeOnClass(Class<?> classType, Class<?> containingClass) {
		Field[] declaredFields = containingClass.getDeclaredFields();
		for (Field field : declaredFields) {
			Class<?> fieldClass = field.getType();
			if (fieldClass == classType) {
				return field;
			}
		}

		// try our parent
		Class<?> parentClass = containingClass.getSuperclass();
		if (parentClass == null) {
			return null;
		}
		return locateFieldByTypeOnClass(classType, parentClass);
	}

	/**
	 * Returns the class name of the entry in the stack that comes before all references to the
	 * given classes.  This is useful for figuring out at runtime who is calling a particular
	 * method. 
	 * <p>
	 * This method can take multiple classes, but you really only need to pass the oldest 
	 * class of disinterest.
	 * 
	 * @param classes the classes to ignore
	 * @return the desired class name
	 */
	public static String getClassNameOlderThan(Class<?>... classes) {

		Throwable t = createThrowableWithStackOlderThan(classes);
		StackTraceElement[] stackTrace = t.getStackTrace();
		return stackTrace[0].getClassName();
	}

	/**
	 * Creates a throwable whose stack trace is based upon the current call stack, with any 
	 * information coming before, and including, the given classes removed.
	 * <p>
	 * This method can take multiple classes, but you really only need to pass the oldest 
	 * class of disinterest.
	 * 
	 * @param classes the classes to ignore
	 * @return the new throwable
	 */
	public static Throwable createThrowableWithStackOlderThan(Class<?>... classes) {

		List<String> toFind =
			Arrays.stream(classes).map(c -> c.getName()).collect(Collectors.toList());

		if (toFind.isEmpty()) {
			// Always ignore our class.  We get this for free if the client passes in any
			// classes.
			toFind.add(0, ReflectionUtilities.class.getName());
		}

		Throwable t = new Throwable();
		StackTraceElement[] trace = t.getStackTrace();
		int lastIgnoreIndex = -1;
		for (int i = 0; i < trace.length; i++) {

			StackTraceElement element = trace[i];
			String className = element.getClassName();
			int nameIndex = toFind.indexOf(className);
			if (nameIndex != -1) {
				lastIgnoreIndex = i;
			}
			else {
				// not a class of interest; if we have already seen our muse, then we are done
				if (lastIgnoreIndex != -1) {
					break;
				}
			}
		}

		if (lastIgnoreIndex == -1) {
			throw new AssertException("Did not find the following classes in the call stack: " +
				Arrays.toString(classes));
		}

		if (lastIgnoreIndex == trace.length - 1) {
			throw new AssertException(
				"Call stack only contains the classes to ignore: " + Arrays.toString(classes));
		}

		int startIndex = lastIgnoreIndex + 1;
		StackTraceElement[] updatedTrace = Arrays.copyOfRange(trace, startIndex, trace.length);
		t.setStackTrace(updatedTrace);
		return t;
	}

	/**
	 * Finds the first occurrence of the given pattern and then stops filtering when it finds 
	 * something that is not that pattern
	 * 
	 * @param trace the trace to update
	 * @param pattern the non-regex patterns used to perform a 
	 * 				  {@link String#contains(CharSequence)} on each {@link StackTraceElement} line
	 * @return the updated trace
	 */
	public static StackTraceElement[] movePastStackTracePattern(StackTraceElement[] trace,
			String pattern) {

		boolean foundIt = false;
		int desiredStartIndex = 0;
		for (int i = 0; i < trace.length; i++) {

			StackTraceElement element = trace[i];
			String traceString = element.toString();

			boolean matches = containsAny(traceString, pattern);
			if (foundIt && !matches) {
				desiredStartIndex = i;
				break;
			}

			foundIt |= matches;
		}

		if (!foundIt) {
			// never contained the pattern--return the original
			return trace;
		}

		StackTraceElement[] updatedTrace =
			Arrays.copyOfRange(trace, desiredStartIndex, trace.length);
		return updatedTrace;
	}

	/**
	 * Uses the given <code>patterns</code> to remove elements from the given stack trace.     
	 * The current implementation will simply perform a <code>toString()</code> on each element and
	 * then check to see if that string contains any of the <code>patterns</code>.
	 * 
	 * @param trace the trace to filter
	 * @param patterns the non-regex patterns used to perform a 
	 * 				   {@link String#contains(CharSequence)} on each {@link StackTraceElement}
	 * 				   line.
	 * @return the filtered trace
	 */
	public static StackTraceElement[] filterStackTrace(StackTraceElement[] trace,
			String... patterns) {

		List<StackTraceElement> list = new ArrayList<>();
		for (StackTraceElement element : trace) {
			String traceString = element.toString();
			if (containsAny(traceString, patterns)) {
				continue;
			}

			list.add(element);
		}
		return list.toArray(new StackTraceElement[list.size()]);

	}

	/**
	 * A convenience method to create a throwable, filtering any lines that contain the given
	 * non-regex patterns.  This can be useful for emitting diagnostic stack traces.
	 * 
	 * @param patterns the non-regex patterns used to perform a 
	 * 				   {@link String#contains(CharSequence)} on each {@link StackTraceElement}
	 * 				   line.
	 * @return the new throwable
	 */
	public static Throwable createFilteredThrowable(String... patterns) {

		Throwable t = createThrowableWithStackOlderThan();
		StackTraceElement[] trace = t.getStackTrace();
		StackTraceElement[] filtered = filterStackTrace(trace, patterns);
		t.setStackTrace(filtered);
		return t;
	}

	/**
	 * A convenience method to create a throwable, filtering boiler-plate Java-related 
	 * lines (e.g., AWT, Swing, Security, etc).  
	 * This can be useful for emitting diagnostic stack traces with reduced noise.
	 * 
	 * @return the new throwable
	 */
	public static Throwable createJavaFilteredThrowable() {

		Throwable t = createThrowableWithStackOlderThan();
		return filterJavaThrowable(t);
	}

	/**
	 * A convenience method to create a throwable, filtering boiler-plate Java-related 
	 * lines (e.g., AWT, Swing, Security, etc).  
	 * This can be useful for emitting diagnostic stack traces with reduced noise.  
	 * 
	 * <p>This method differs from {@link #createJavaFilteredThrowable()} in that this method
	 * returns a String, which is useful when printing log messages without having to directly
	 * print the stack trace.
	 * 
	 * @return the new throwable
	 */
	public static String createJavaFilteredThrowableString() {
		Throwable t = createThrowableWithStackOlderThan();
		Throwable filtered = filterJavaThrowable(t);
		return stackTraceToString(filtered);
	}

	/**
	 * A convenience method to take a throwable, filter boiler-plate Java-related 
	 * lines (e.g., AWT, Swing, Security, etc).  
	 * This can be useful for emitting diagnostic stack traces with reduced noise.
	 * 
	 * @param t the throwable to filter
	 * @return the throwable
	 */
	public static Throwable filterJavaThrowable(Throwable t) {
		StackTraceElement[] trace = t.getStackTrace();
		StackTraceElement[] filtered = filterStackTrace(trace, JAVA_AWT_PATTERN,
			JAVA_REFLECT_PATTERN, JDK_INTERNAL_REFLECT_PATTERN, SWING_JAVA_PATTERN,
			SWING_JAVAX_PATTERN, SECURITY_PATTERN, SUN_AWT_PATTERN, SUN_REFLECT_PATTERN,
			MOCKIT_PATTERN, JUNIT_PATTERN);
		t.setStackTrace(filtered);
		return t;
	}

	private static boolean containsAny(String s, String... patterns) {
		for (String p : patterns) {
			if (s.contains(p)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns a string which is a printout of a stack trace for each thread running in the
	 * current JVM
	 * @return the stack trace string
	 */
	public static String createStackTraceForAllThreads() {
		Map<Thread, StackTraceElement[]> allStackTraces = Thread.getAllStackTraces();
		Set<Entry<Thread, StackTraceElement[]>> entrySet = allStackTraces.entrySet();
		StringBuilder builder = new StringBuilder();
		for (Entry<Thread, StackTraceElement[]> entry : entrySet) {
			builder.append("Thread: " + entry.getKey().getName()).append('\n');
			StackTraceElement[] value = entry.getValue();
			for (StackTraceElement stackTraceElement : value) {
				builder.append('\t').append("at ").append(stackTraceElement).append('\n');
			}
		}

		return builder.toString();
	}

	/**
	 * Returns an ordered set of interfaces and classes that are shared amongst the items in 
	 * the list.
	 * <p>
	 * The order of the items is as they are first encountered, favoring interfaces before 
	 * classes.  Further, interface hierarchies are examined before concrete parent extensions.
	 * <p>
	 * If the given items have no parents in common, then the result will be a list with
	 * only <code>Object.class</code>.
	 * 
	 * @param list the items to examine
	 * @return the set of items
	 */
	public static LinkedHashSet<Class<?>> getSharedHierarchy(List<?> list) {

		Object seed = list.get(0);

		LinkedHashSet<Class<?>> master = new LinkedHashSet<>();
		Class<?> start = seed.getClass();
		boolean shareType = list.stream().allMatch(t -> t.getClass().equals(start));
		if (shareType) {
			master.add(start);
		}

		LinkedHashSet<Class<?>> parents = getAllParents(seed.getClass());

		Iterator<?> iterator = list.iterator();
		iterator.next(); // we already grabbed the seed
		while (iterator.hasNext()) {
			Object o = iterator.next();
			LinkedHashSet<Class<?>> next = getAllParents(o.getClass());
			parents.retainAll(next);
		}

		master.addAll(parents);

		if (master.isEmpty()) {
			master.add(Object.class);
		}

		return master;
	}

	/**
	 * Returns an ordered set of parent interfaces and classes that are shared 
	 * amongst the items in the list.
	 * <p>
	 * The order of the items is as they are first encountered, favoring interfaces before 
	 * classes.  Further, interface hierarchies are examined before concrete parent extensions.
	 * <p>
	 * If the given items have no parents in common, then the result will be a list with
	 * only <code>Object.class</code>.
	 * 
	 * @param list the items to examine
	 * @return the set of items
	 */
	public static LinkedHashSet<Class<?>> getSharedParents(List<?> list) {

		Object seed = list.get(0);
		LinkedHashSet<Class<?>> master = getAllParents(seed.getClass());

		Iterator<?> iterator = list.iterator();
		iterator.next(); // we already grabbed the seed
		while (iterator.hasNext()) {
			Object o = iterator.next();
			LinkedHashSet<Class<?>> next = getAllParents(o.getClass());
			master.retainAll(next);
		}

		if (master.isEmpty()) {
			master.add(Object.class);
		}

		return master;
	}

	/**
	 * Turns the given {@link Throwable} into a String version of its 
	 * {@link Throwable#printStackTrace()} method.
	 * 
	 * @param t the throwable
	 * @return the string
	 */
	public static String stackTraceToString(Throwable t) {
		return stackTraceToString(t.getMessage(), t);
	}

	/**
	 * Turns the given {@link Throwable} into a String version of its 
	 * {@link Throwable#printStackTrace()} method.
	 * 
	 * @param message the preferred message to use.  If null, the throwable message will be used
	 * @param t the throwable
	 * @return the string
	 */
	public static String stackTraceToString(String message, Throwable t) {
		StringBuilder sb = new StringBuilder();

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		PrintStream ps = new PrintStream(baos);

		if (message != null) {
			ps.println(message);
		}
		else {
			String throwableMessage = t.getMessage();
			if (throwableMessage != null) {
				ps.println(throwableMessage);
			}
		}

		t.printStackTrace(ps);
		sb.append(baos.toString());
		ps.close();
		try {
			baos.close();
		}
		catch (IOException e) {
			// shouldn't happen--not really connected to the system
		}

		return sb.toString();
	}

	/**
	 * Returns an order set of all interfaces implemented and classes extended for the entire
	 * type structure of the given class. 
	 * <p>
	 * If <code>Object.class</code> is passed to this method, then it will be returned in the 
	 * result of this method.
	 * 
	 * @param c the class to introspect
	 * @return the set of parents
	 */
	public static LinkedHashSet<Class<?>> getAllParents(Class<?> c) {

		LinkedHashSet<Class<?>> l = new LinkedHashSet<>();
		if (Object.class.equals(c)) {
			l.add(Object.class);
			return l; // Object has no parents
		}

		doGetAllParents(c, l);
		return l;
	}

	private static void doGetAllParents(Class<?> c, LinkedHashSet<Class<?>> accumulator) {

		Class<?>[] interfaces = c.getInterfaces();
		accumulator.addAll(Arrays.asList(interfaces));

		for (Class<?> clazz : interfaces) {
			doGetAllParents(clazz, accumulator);
		}

		Class<?> superclass = c.getSuperclass();
		if (superclass != null) {
			accumulator.add(superclass);
			doGetAllParents(superclass, accumulator);
		}
	}

	/**
	 * Returns the type arguments for the given base class and extension.
	 * 
	 * <p>Caveat: this lookup will only work if the given child class is a concrete class that
	 * has its type arguments specified.  For example, these cases will work:
	 * <pre>
	 * 		// anonymous class definition
	 * 		List&lt;String&gt; myList = new ArrayList&lt;String&gt;() {
	 *			...
	 *		};
	 *
	 *		// class definition
	 *		public class MyList implements List&lt;String&gt; {
	 * </pre> 
	 * 
	 * Whereas this case will not work:
	 * <pre>
	 * 		// local variable with the type specified
	 * 		List&lt;String&gt; myList = new ArrayList&lt;String&gt;();
	 * </pre>
	 * 
	 * <p>Note: a null entry in the result list will exist for any type that was unrecoverable
	 * 
	 * 
	 * @param <T> the type of the base and child class
	 * @param baseClass the base class
	 * @param childClass the child class
	 * @return the type arguments
	 */
	public static <T> List<Class<?>> getTypeArguments(Class<T> baseClass,
			Class<? extends T> childClass) {

		Objects.requireNonNull(baseClass);
		Objects.requireNonNull(childClass);

		Map<Type, Type> resolvedTypesDictionary = new HashMap<>();
		Type baseClassAsType =
			walkClassHierarchyAndResolveTypes(baseClass, resolvedTypesDictionary, childClass);

		// try to resolve type arguments defined by 'baseClass' to the raw runtime class 
		Type[] baseClassDeclaredTypeArguments = getDeclaredTypeArguments(baseClassAsType);
		return resolveBaseClassTypeArguments(resolvedTypesDictionary,
			baseClassDeclaredTypeArguments);
	}

	private static <T> Type walkClassHierarchyAndResolveTypes(Class<T> baseClass,
			Map<Type, Type> resolvedTypes, Type type) {

		if (type == null) {
			return null;
		}

		if (equals(type, baseClass)) {
			return type;
		}

		if (type instanceof Class) {

			Class<?> clazz = (Class<?>) type;
			Type[] interfaceTypes = clazz.getGenericInterfaces();
			Set<Type> toCheck = new HashSet<>();
			toCheck.addAll(Arrays.asList(interfaceTypes));

			Type parentType = clazz.getGenericSuperclass();
			toCheck.add(parentType);

			for (Type t : toCheck) {
				Type result = walkClassHierarchyAndResolveTypes(baseClass, resolvedTypes, t);
				if (equals(result, baseClass)) {
					return result;
				}
			}

			return parentType;
		}

		ParameterizedType parameterizedType = (ParameterizedType) type;
		Class<?> rawType = (Class<?>) parameterizedType.getRawType();
		Type[] actualTypeArguments = parameterizedType.getActualTypeArguments();
		TypeVariable<?>[] typeParameters = rawType.getTypeParameters();
		for (int i = 0; i < actualTypeArguments.length; i++) {
			resolvedTypes.put(typeParameters[i], actualTypeArguments[i]);
		}

		if (rawType.equals(baseClass)) {
			return rawType;
		}

		Type[] interfaceTypes = rawType.getGenericInterfaces();
		Set<Type> toCheck = new HashSet<>();
		toCheck.addAll(Arrays.asList(interfaceTypes));

		Type parentType = rawType.getGenericSuperclass();
		toCheck.add(parentType);

		for (Type t : toCheck) {
			Type result = walkClassHierarchyAndResolveTypes(baseClass, resolvedTypes, t);
			if (equals(result, baseClass)) {
				return result;
			}
		}

		return parentType;
	}

	private static boolean equals(Type type, Class<?> c) {
		Class<?> typeClass = getClass(type);
		if (typeClass == null) {
			return false;
		}
		return typeClass.equals(c);
	}

	private static Class<?> getClass(Type type) {

		if (type instanceof Class) {
			return (Class<?>) type;
		}

		if (type instanceof ParameterizedType) {
			return getClass(((ParameterizedType) type).getRawType());
		}

		if (type instanceof GenericArrayType) {
			GenericArrayType arrayType = (GenericArrayType) type;
			Type componentType = arrayType.getGenericComponentType();
			Class<?> componentClass = getClass(componentType);
			if (componentClass != null) {
				return Array.newInstance(componentClass, 0).getClass();
			}
			return null;
		}

		return null;
	}

	private static List<Class<?>> resolveBaseClassTypeArguments(Map<Type, Type> resolvedTypes,
			Type[] genericTypeArguments) {
		List<Class<?>> typeArgumentsAsClasses = new ArrayList<>();
		for (Type baseType : genericTypeArguments) {
			while (resolvedTypes.containsKey(baseType)) {
				baseType = resolvedTypes.get(baseType);
			}
			typeArgumentsAsClasses.add(getClass(baseType));
		}
		return typeArgumentsAsClasses;
	}

	private static Type[] getDeclaredTypeArguments(Type type) {
		if (type instanceof Class) {
			return ((Class<?>) type).getTypeParameters();
		}
		return ((ParameterizedType) type).getActualTypeArguments();
	}

}
