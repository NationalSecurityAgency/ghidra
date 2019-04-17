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

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import ghidra.util.SystemUtilities;

public class ReflectionUtilitiesTest {

	@Test
	public void testGetClassNameAfter() {

		String caller = ReflectionUtilities.getClassNameOlderThan(getClass());
		assertThat(caller, not(equalTo(getClass().getName())));
	}

	@Test
	public void testGetClassNameAfter_NoClasses() {

		String caller = ReflectionUtilities.getClassNameOlderThan();
		assertThat(caller, is(equalTo(ReflectionUtilitiesTest.class.getName())));
	}

	@Test
	public void testGetClassNameAfter_InvalidClasses() {

		try {
			ReflectionUtilities.getClassNameOlderThan(SystemUtilities.class);
			fail("Did not get an exception passing a class not in the stack");
		}
		catch (Exception e) {
			// good
		}
	}

	@Test
	public void testGetClassNameAfter_AnotherClass() {

		NestedTestClass nested = new NestedTestClass();
		String caller = nested.getCallerFromOneLevel();
		assertThat(caller, is(equalTo(ReflectionUtilitiesTest.class.getName())));
	}

	@Test
	public void testGetClassNameAfter_AnotherClass_MultipleMethodCalls() {

		NestedTestClass nested = new NestedTestClass();
		String caller = nested.getCallerFromTwoLevels();
		assertThat(caller, is(equalTo(ReflectionUtilitiesTest.class.getName())));
	}

	@Test
	public void testMovePastStackTracePattern() {

		//@formatter:off
		StackTraceElement[] trace = { 
			element("Class1", "method"),
			element("Class2", "method"),
			element("Class3", "method"),
			element("OtherClass", "otherCall"),
			element("ThirdClass", "doIt"),
			element("FinalClass", "maybeDoIt"),
			element("Class4", "maybeDoIt"),
		};
		//@formatter:on

		StackTraceElement[] updated =
			ReflectionUtilities.movePastStackTracePattern(trace, "method");

		assertThat(updated.length, is(4));
		assertThat(updated[0].getClassName(), is("OtherClass.class"));
		assertThat(updated[3].getClassName(), is("Class4.class"));
	}

	@Test
	public void testCreateFilteredThrowable() {

		Throwable t = ReflectionUtilities.createFilteredThrowable("org.junit");
		StackTraceElement[] updated = t.getStackTrace();

		for (StackTraceElement element : updated) {
			assertThat(element.toString(), not(containsString("org.junit")));
		}
	}

	// verify that we can discover parent template types when given a subclass implementation
	@Test
	public void testRuntimeTypeDiscovery() {

		// unfortunately, this won't work
		RuntimeBaseType<Integer, Float> runtimeBaseType = new RuntimeBaseType<>();
		List<Class<?>> typeArguments =
			ReflectionUtilities.getTypeArguments(RuntimeBaseType.class, runtimeBaseType.getClass());
		assertTrue("Did not get a list with null values for each declared type on a base class",
			!typeArguments.isEmpty());
		assertNull("Did not get a null value as expected for a declared type",
			typeArguments.get(0));
		assertNull("Did not get a null value as expected for a declared type",
			typeArguments.get(1));

		// also unfortunate, we cannot get the template types that are declared at usage time, and
		// not by definition
		ChildTypeWithPassThroughTypes<Integer, Float> passThroughType =
			new ChildTypeWithPassThroughTypes<>();
		List<Class<?>> passThroughArguments =
			ReflectionUtilities.getTypeArguments(RuntimeBaseType.class, passThroughType.getClass());
		assertTrue("Unable to resolve parent types from child implementation",
			!passThroughArguments.isEmpty());
		assertNull("Did not get a null value as expected for a declared type",
			typeArguments.get(0));
		assertNull("Did not get a null value as expected for a declared type",
			typeArguments.get(1));

		// this class has type parameters declared in the class definition, which we can detect
		ChildTypeWithActualTypes actualType = new ChildTypeWithActualTypes();
		List<Class<?>> actualTypeArguments =
			ReflectionUtilities.getTypeArguments(RuntimeBaseType.class, actualType.getClass());
		assertTrue("Unable to resolve parent types from child implementation",
			!actualTypeArguments.isEmpty());
		assertEquals("Did not get the expected type parameter", String.class,
			actualTypeArguments.get(0));
		assertEquals("Did not get the expected type parameter", Object.class,
			actualTypeArguments.get(1));

		// this class too has type parameters declared in the class definition, which we can detect
		BabyType babyType = new BabyType();
		List<Class<?>> babyTypeArguments =
			ReflectionUtilities.getTypeArguments(RuntimeBaseType.class, babyType.getClass());
		assertTrue("Unable to resolve parent types from child implementation",
			!babyTypeArguments.isEmpty());
		assertEquals("Did not get the expected type parameter", Integer.class,
			babyTypeArguments.get(0));
		assertEquals("Did not get the expected type parameter", String.class,
			babyTypeArguments.get(1));
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private StackTraceElement element(String className, String methodName) {
		return new StackTraceElement(className + ".class", methodName, className + ".java", 1);
	}

	private class NestedTestClass {

		String getCallerFromOneLevel() {
			String name = ReflectionUtilities.getClassNameOlderThan(NestedTestClass.class);
			return name;
		}

		String getCallerFromTwoLevels() {
			String caller = levelTwo();
			return caller;
		}

		private String levelTwo() {
			String name = ReflectionUtilities.getClassNameOlderThan(NestedTestClass.class);
			return name;
		}
	}

	private class RuntimeBaseType<T, J> {
		// stub
	}

	private class ChildTypeWithPassThroughTypes<X, Y> extends RuntimeBaseType<X, Y> {
		// stub
	}

	private class ChildTypeWithActualTypes extends RuntimeBaseType<String, Object> {
		// stub
	}

	private class BabyType extends ChildTypeWithPassThroughTypes<Integer, String> {
		// stub
	}
}
