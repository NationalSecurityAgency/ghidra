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
package generic.test;

import java.lang.reflect.*;
import java.util.ArrayList;
import java.util.List;

import utilities.util.reflection.ReflectionUtilities;

/** 
 * Actually, not.  At least not soon...all the *TestCase classes now can
 * be split apart into static-style utility methods, and instance-type
 * test harness/scaffold methods, but they will need to live at their
 * respective layer, not all here in Base.
 * 
 * Future home of utility methods (many methods of TestCase can be put here).
 * <P>
 * A primary motivating factor for creating this class is to gain access to some of the myriad 
 * functionality in TestCase without loading its static data.
 * 
 */
public class TestUtils {
	private TestUtils() {
		// utils class
	}

	/**
	 * Returns a string which is a printout of a stack trace for each thread running in the
	 * current JVM
	 * @return the stack trace string
	 */
	public static String createStackTraceForAllThreads() {
		return ReflectionUtilities.createStackTraceForAllThreads();
	}

	/**
	 * Sets the instance field by the given name on the given object 
	 * instance.  
	 * <p>
	 * Note: if the field is static, then the <code>ownerInstance</code> field 
	 * can be the class of the object that contains the variable.
	 * 
	 * @param  fieldName The name of the field to retrieve.
	 * @param  ownerInstance The object instance from which to get the 
	 *         variable instance.
	 * @param  value The value to use when setting the given field
	 * @throws RuntimeException if there is a problem accessing the field
	 *         using reflection.  A RuntimeException is used so that calling
	 *         tests can avoid using a try/catch block, but will still fail
	 *         when an error is encountered.
	 * @see    Field#set(Object, Object)
	 */
	public static void setInstanceField(String fieldName, Object ownerInstance, Object value)
			throws RuntimeException {
		if (ownerInstance == null) {
			throw new NullPointerException("Owner of instance field cannot be null");
		}

		Class<?> objectClass =
			(ownerInstance instanceof Class) ? (Class<?>) ownerInstance : ownerInstance.getClass();
		try {
			// get the field from the class object 
			Field field = ReflectionUtilities.locateFieldObjectOnClass(fieldName, objectClass);

			// open up the field so that we have access
			field.setAccessible(true);

			// set the field from the object instance that we were provided
			field.set(ownerInstance, value);
		}
		catch (Exception e) {
			throw new RuntimeException("Unable to use reflection to obtain " + "field: " +
				fieldName + " from class: " + objectClass, e);
		}
	}

	/**
	 * Gets the instance field by the given name on the given object 
	 * instance.  The value is a primitive wrapper if it is a primitive type.
	 * <p>
	 * Note: if the field is static, then the <code>ownerInstance</code> field 
	 * can be the class of the object that contains the variable.
	 * 
	 * @param  fieldName The name of the field to retrieve.
	 * @param  ownerInstance The object instance from which to get the 
	 *         variable instance.
	 * @return The field instance.
	 * @throws RuntimeException if there is a problem accessing the field
	 *         using reflection.  A RuntimeException is used so that calling
	 *         tests can avoid using a try/catch block, but will still fail
	 *         when an error is encountered.
	 * @see    Field#get(java.lang.Object)
	 * @since  Tracker Id 267
	 */
	public static Object getInstanceField(String fieldName, Object ownerInstance)
			throws RuntimeException {
		if (ownerInstance == null) {
			throw new NullPointerException("Owner of instance field cannot be null");
		}

		Class<?> objectClass =
			(ownerInstance instanceof Class) ? (Class<?>) ownerInstance : ownerInstance.getClass();
		Object result = null;
		try {
			// get the field from the class object 
			Field field = ReflectionUtilities.locateFieldObjectOnClass(fieldName, objectClass);

			// open up the field so that we have access
			field.setAccessible(true);

			// get the field from the object instance that we were provided
			result = field.get(ownerInstance);
		}
		catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException("Unable to use reflection to obtain " + "field: " +
				fieldName + " from class: " + objectClass, e);
		}

		return result;
	}

	/**
	 * Gets all fields of the given object.  Only objects on the immediate instance are 
	 * returned.
	 * 
	 * @param ownerInstance the object from which to get fields
	 * @return the fields
	 */
	public static List<Object> getAllInstanceFields(Object ownerInstance) {
		if (ownerInstance == null) {
			throw new NullPointerException("Owner of instance field cannot be null");
		}

		Class<?> objectClass =
			(ownerInstance instanceof Class) ? (Class<?>) ownerInstance : ownerInstance.getClass();
		List<Object> results = new ArrayList<>();

		Field[] fields = objectClass.getDeclaredFields();
		for (Field field : fields) {
			field.setAccessible(true);
			try {
				Object fieldInstance = field.get(ownerInstance);
				results.add(fieldInstance);
			}
			catch (Exception e) {
				throw new RuntimeException(
					"Unable to use reflection to obtain fields from class: " + objectClass, e);
			}
		}

		return results;
	}

	/**
	 * Uses reflection to execute the method denoted by the given method
	 * name.  If any value is returned from the method execution, then it 
	 * will be returned from this method.  Otherwise, <code>null</code> is returned.
	 * <p>
	 * Note: if the method is static, then the <code>ownerInstance</code> field 
	 * can be the class of the object that contains the method.
	 * 
	 * @param methodName The name of the method to execute.
	 * @param ownerInstance The object instance of which the method will be
	 *        executed.
	 * @param parameterTypes The parameter <b>types</b> that the method takes.
	 * @param args The parameter values that should be passed to the method.
	 *        This value can be null or zero length if there are no parameters
	 *        to pass
	 * @return The return value as returned from executing the method.
	 * @see    Method#invoke(java.lang.Object, java.lang.Object[])
	 * @throws RuntimeException if there is a problem accessing the field
	 *         using reflection.  A RuntimeException is used so that calling
	 *         tests can avoid using a try/catch block, but will still fail
	 *         when an error is encountered.
	 * @since  Tracker Id 267
	 */
	public static Object invokeInstanceMethod(String methodName, Object ownerInstance,
			Class<?>[] parameterTypes, Object[] args) throws RuntimeException {
		if (ownerInstance == null) {
			throw new NullPointerException("Owner of instance field cannot be null");
		}

		Class<?> objectClass =
			(ownerInstance instanceof Class) ? (Class<?>) ownerInstance : ownerInstance.getClass();
		Object result = null;

		try {

			// get the method object to call
			Method method = locateMethodObjectOnClass(methodName, objectClass, parameterTypes);

			if (method == null) {
				throw new NoSuchMethodException("Unable to find a method by " + "the name \"" +
					methodName + "\" on the class " + objectClass + " or any of its parent " +
					"implementations.");
			}

			// make sure we have access
			method.setAccessible(true);

			// execute the method and get the result
			result = method.invoke(ownerInstance, args);
		}
		catch (Exception e) {
			throw new RuntimeException("Unable to use reflection to call " + "method: " +
				methodName + " from class: " + objectClass, e);
		}

		return result;
	}

	/**
	 * Uses reflection to execute the method denoted by the given method
	 * name.  If any value is returned from the method execution, then it 
	 * will be returned from this method.  Otherwise, <code>null</code> is returned.
	 * <p>
	 * Note: if the method is static, then the <code>ownerInstance</code> field 
	 * can be the class of the object that contains the method.
	 * 
	 * <P>This method is just a convenience for calling 
	 * {@link #invokeInstanceMethod(String, Object, Class[], Object[])}.  As the following 
	 * example shows, this method's uses is a bit cleaner:
	 * <PRE>
	 *  	// The call below is equivalent to calling: <CODE> System.out.println("Hi")
	 * 	invokeInstanceMethod("println", System.out, Arrays.asList(String.class), Arrays.asList("Hi"));
	 * 	</CODE>
	 * </PRE>
	 * 
	 * @param methodName The name of the method to execute.
	 * @param ownerInstance The object instance of which the method will be
	 *        executed.
	 * @param parameterTypes The parameter <b>types</b> that the method takes.
	 * @param args The parameter values that should be passed to the method.
	 *        This value can be null or zero length if there are no parameters
	 *        to pass
	 * @return The return value as returned from executing the method.
	 * @throws RuntimeException if there is a problem accessing the field
	 *         using reflection.  A RuntimeException is used so that calling
	 *         tests can avoid using a try/catch block, but will still fail
	 *         when an error is encountered.
	 */
	public static Object invokeInstanceMethod(String methodName, Object ownerInstance,
			List<Class<?>> parameterTypes, List<Object> args) throws RuntimeException {

		Class<?>[] parameterTypesArray = new Class[parameterTypes.size()];
		parameterTypes.toArray(parameterTypesArray);
		return invokeInstanceMethod(methodName, ownerInstance, parameterTypesArray, args.toArray());
	}

	/**
	 * Uses reflection to execute the method denoted by the given method
	 * name.  If any value is returned from the method execution, then it 
	 * will be returned from this method.  Otherwise, <code>null</code> is returned.
	 * <p>
	 * Note: if the method is static, then the <code>ownerInstance</code> field 
	 * can be the class of the object that contains the method.
	 * 
	 * <P>If the method you are calling takes no parameters, then call 
	 * {@link #invokeInstanceMethod(String, Object)} instead.
	 * 
	 * <P>This method is just a convenience for calling 
	 * {@link #invokeInstanceMethod(String, Object, Class[], Object[])} when the method only
	 * takes a single parameter, so that you don't have the ugliness of creating arrays as the
	 * parameters for this method.
	 * 
	 * <P>As an example:
	 * <PRE>
	 *  	// The call below is equivalent to calling: <CODE> System.out.println("Hi")
	 * 	invokeInstanceMethod("println", System.out, String.class, "Hi");
	 * 	</CODE>
	 * </PRE>
	 * 
	 * @param methodName The name of the method to execute.
	 * @param ownerInstance The object instance of which the method will be
	 *        executed.
	 * @param parameterType The parameter types that the method takes.
	 * @param arg The parameter value that should be passed to the method.
	 * @return The return value as returned from executing the method.
	 * @throws RuntimeException if there is a problem accessing the field
	 *         using reflection.  A RuntimeException is used so that calling
	 *         tests can avoid using a try/catch block, but will still fail
	 *         when an error is encountered.
	 */
	public static Object invokeInstanceMethod(String methodName, Object ownerInstance,
			Class<?> parameterType, Object arg) throws RuntimeException {

		return invokeInstanceMethod(methodName, ownerInstance, new Class[] { parameterType },
			new Object[] { arg });
	}

	/**
	 * Uses reflection to execute the method denoted by the given method
	 * name.  If any value is returned from the method execution, then it 
	 * will be returned from this method.  Otherwise, <code>null</code> is returned.
	 * <p>
	 * Note: if the method is static, then the <code>ownerInstance</code> field 
	 * can be the class of the object that contains the method.
	 * 
	 * <P><B>Warning: The exact class of each <CODE>arg</CODE> will be used as the class type
	 * of the parameter for the method being called.  If the method you are calling takes 
	 * parameters that do not match exactly the class of the args you wish to use, then 
	 * call {@link #invokeInstanceMethod(String, Object, List, List)} instead so that you 
	 * can specify the parameter types explicitly.
	 * </B>
	 * 
	 * <P>If the method you are calling takes no parameters, then call 
	 * {@link #invokeInstanceMethod(String, Object)} instead.
	 * 
	 * <P>This method is just a convenience for calling 
	 * {@link #invokeInstanceMethod(String, Object, Class[], Object[])} when the method only
	 * takes a single parameter, so that you don't have the ugliness of creating arrays as the
	 * parameters for this method.
	 * 
	 * <P>As an example:
	 * <PRE>
	 *  	// The call below is equivalent to calling: <CODE> System.out.println("Hi")
	 * 	invokeInstanceMethod("println", System.out, "Hi");
	 * 
	 * 	// This call is equivalent to the one above
	 * 	invokeInstanceMethod("println", System.out, Arrays.asList(String.class), Arrays.asList("Hi"));
	 * 	
	 * 	</CODE>
	 * </PRE>
	 * 
	 * @param methodName The name of the method to execute.
	 * @param ownerInstance The object instance of which the method will be
	 *        executed.
	 * @param args The parameter value that should be passed to the method.
	 * @return The return value as returned from executing the method.
	 * @throws RuntimeException if there is a problem accessing the field
	 *         using reflection.  A RuntimeException is used so that calling
	 *         tests can avoid using a try/catch block, but will still fail
	 *         when an error is encountered.
	 */
	public static Object invokeInstanceMethod(String methodName, Object ownerInstance,
			Object... args) throws RuntimeException {

		Class<?>[] classes = getClasses(args);
		return invokeInstanceMethod(methodName, ownerInstance, classes, args);
	}

	private static Class<?>[] getClasses(Object[] args) {

		Class<?>[] classes = new Class[args.length];
		for (int i = 0; i < args.length; i++) {
			classes[i] = args[i].getClass();
		}
		return classes;
	}

	/**
	 * This method is just a "pass through" method for 
	 * {@link #invokeInstanceMethod(String, Object, Class[], Object[])} so 
	 * that callers do not need to pass null to that method when the 
	 * underlying instance method does not have any parameters. 
	 * 
	 * @param methodName The name of the method to execute.
	 * @param ownerInstance The object instance of which the method will be
	 *        executed.
	 * @return The return value as returned from executing the method.
	 * @see    Method#invoke(java.lang.Object, java.lang.Object[])
	 * @throws RuntimeException if there is a problem accessing the field
	 *         using reflection.  A RuntimeException is used so that calling
	 *         tests can avoid using a try/catch block, but will still fail
	 *         when an error is encountered.
	 * @see    #invokeInstanceMethod(String, Object, Class[], Object[])
	 */
	public static Object invokeInstanceMethod(String methodName, Object ownerInstance)
			throws RuntimeException {
		return invokeInstanceMethod(methodName, ownerInstance, (Class[]) null, null);
	}

	/**
	 * Uses reflection to execute the constructor for the given class with the given parameters.
	 * The new instance of the given class will be returned.
	 * <p>
	 * 
	 * @param containingClass The class that contains the desired constructor.
	 * @param parameterTypes The parameter <b>types</b> that the constructor takes.
	 *        This value can be null or zero length if there are no parameters
	 *        to pass
	 * @param args The parameter values that should be passed to the constructor.
	 *        This value can be null or zero length if there are no parameters
	 *        to pass
	 * @return The new class instance
	 * @throws RuntimeException if there is a problem accessing the constructor
	 *         using reflection.  A RuntimeException is used so that calling
	 *         tests can avoid using a try/catch block, but will still fail
	 *         when an error is encountered.
	 */
	public static Object invokeConstructor(Class<?> containingClass, Class<?>[] parameterTypes,
			Object[] args) throws RuntimeException {

		Object result = null;

		try {
			Constructor<?> constructor = locateConstructorOnClass(containingClass, parameterTypes);
			if (constructor == null) {
				throw new NoSuchMethodException("Unable to find a constructor " + "on the class " +
					containingClass + " with the given parameters");
			}

			// make sure we have access
			constructor.setAccessible(true);

			// execute the method and get the result
			result = constructor.newInstance(args);
		}
		catch (Exception e) {
			throw new RuntimeException(
				"Unable to use reflection to call " + "constructor from class: " + containingClass,
				e);
		}

		return result;
	}

	/**
	 * A convenience method that can be statically  imported to use with the class, allowing 
	 * you to avoid your own ugly manual array creation.
	 * 
	 * @param classes the classes
	 * @return the classes array
	 */
	public static Class<?>[] argTypes(Class<?>... classes) {
		return classes;
	}

	/**
	 * A convenience method that can be statically  imported to use with the class, allowing 
	 * you to avoid your own ugly manual array creation.
	 * 
	 * @param objects the objects
	 * @return the objects array
	 */
	public static Object[] args(Object... objects) {
		return objects;
	}

	private static Constructor<?> locateConstructorOnClass(Class<?> containingClass,
			Class<?>[] parameterTypes) {

		return ReflectionUtilities.locateConstructorOnClass(containingClass, parameterTypes);
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
	private static Method locateMethodObjectOnClass(String methodName, Class<?> containingClass,
			Class<?>[] parameterTypes) {
		return ReflectionUtilities.locateMethodObjectOnClass(methodName, containingClass,
			parameterTypes);
	}

	/**
	 * Get the first field object contained within object ownerInstance which has the type classType.
	 * This method is only really useful if it is known that only a single field of 
	 * classType exists within the ownerInstance.
	 * 
	 * @param <T> the type
	 * @param classType the class type of the desired field
	 * @param ownerInstance the object instance that owns the field
	 * @return field object of type classType or null
	 */
	@SuppressWarnings("unchecked")
	// we know the type is safe, since we search by class type
	public static <T> T getInstanceFieldByClassType(Class<T> classType, Object ownerInstance) {
		if (ownerInstance == null) {
			throw new NullPointerException("Owner of instance field cannot be null");
		}

		Class<?> objectClass =
			(ownerInstance instanceof Class) ? (Class<?>) ownerInstance : ownerInstance.getClass();

		Object result = null;
		try {
			// get the field from the class object 
			Field field = locateFieldByTypeOnClass(classType, objectClass);
			if (field == null) {
				return null;
			}

			// open up the field so that we have access
			field.setAccessible(true);

			// get the field from the object instance that we were provided
			result = field.get(ownerInstance);
		}
		catch (Exception e) {
			throw new RuntimeException("Unable to use reflection to obtain " + "a field of type: " +
				classType.getName() + " from class: " + objectClass, e);
		}

		return (T) result;
	}

	/**
	 * Get the first field specification contained within containingClass which has the type classType.
	 * This method is only really useful if it is known that only a single field of 
	 * classType exists within the containingClass hierarchy.
	 * 
	 * @param classType the class
	 * @param containingClass the class that contains a field of the given type
	 * @return field which corresponds to type classType or null
	 */
	public static Field locateFieldByTypeOnClass(Class<?> classType, Class<?> containingClass) {
		return ReflectionUtilities.locateFieldByTypeOnClass(classType, containingClass);
	}

}
