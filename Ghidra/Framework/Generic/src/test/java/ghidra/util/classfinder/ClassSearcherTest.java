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
package ghidra.util.classfinder;

import static org.junit.Assert.*;

import java.lang.reflect.Constructor;

import org.junit.Test;

public class ClassSearcherTest {
	public enum Canary {
		ALIVE, DEAD;
	}

	public static Canary canary;

	public interface TestSuper {
	}

	public interface WrongSuper {
	}

	public static class ClassWithStaticInitializerSideEffects implements TestSuper {
		static {
			canary = Canary.DEAD;
		}
	}

	/**
	 * Test that our safe(r) version of {@link Class#forName(String)} does not invoke any static
	 * initializer.
	 * 
	 * @throws Exception because
	 */
	@Test
	public void testForNameSafeNoClinit() throws Exception {
		canary = Canary.ALIVE;

		Class<? extends TestSuper> found = ClassSearcher.forNameSafe(
			"ghidra.util.classfinder.ClassSearcherTest$ClassWithStaticInitializerSideEffects",
			TestSuper.class, getClass().getClassLoader());
		assertNotNull(found);
		assertEquals(Canary.ALIVE, canary);
		Constructor<? extends TestSuper> constructor = found.getConstructor();
		assertEquals(Canary.ALIVE, canary);
		TestSuper instance = constructor.newInstance();
		assertNotNull(instance);
		assertEquals(Canary.DEAD, canary);
	}

	@Test
	public void testForNameSafeNoClinitErr() throws Exception {
		canary = Canary.ALIVE;

		try {
			ClassSearcher.forNameSafe(
				"ghidra.util.classfinder.ClassSearcherTest$ClassWithStaticInitializerSideEffects",
				WrongSuper.class, getClass().getClassLoader());
			fail("Should not have permitted the class");
		}
		catch (ClassCastException e) {
			// pass
		}
		assertEquals(Canary.ALIVE, canary);
	}
}
