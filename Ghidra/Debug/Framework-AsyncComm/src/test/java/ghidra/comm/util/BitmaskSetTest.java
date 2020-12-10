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
package ghidra.comm.util;

import static org.junit.Assert.*;

import java.io.*;
import java.net.URI;
import java.util.*;

import javax.tools.*;
import javax.tools.JavaCompiler.CompilationTask;
import javax.tools.JavaFileObject.Kind;

import org.junit.Test;

import ghidra.util.Msg;

public class BitmaskSetTest {
	public enum TestUniverse implements BitmaskUniverse {
		FIRST(1 << 0), SECOND(1 << 1), THIRD(1 << 2), FOURTH(1 << 3);

		TestUniverse(long mask) {
			this.mask = mask;
		}

		final long mask;

		@Override
		public long getMask() {
			return mask;
		}
	}

	public enum TestAlternate implements BitmaskUniverse {
		FIFTH(1 << 4), SIXTH(1 << 5), SEVENTH(1 << 6), EIGHTH(1 << 7);

		TestAlternate(long mask) {
			this.mask = mask;
		}

		final long mask;

		@Override
		public long getMask() {
			return mask;
		}
	}

	Set<Integer> intOf0 = new HashSet<>();
	Set<Integer> intOf3 = new HashSet<>(Arrays.asList(new Integer[] { 0, 1, 2 }));
	Set<String> strOf0 = new HashSet<>();

	BitmaskSet<TestUniverse> setOf0 = BitmaskSet.of();
	BitmaskSet<TestUniverse> setOf1 = BitmaskSet.of(TestUniverse.FIRST);
	BitmaskSet<TestUniverse> setOf2 = BitmaskSet.of(TestUniverse.FIRST, TestUniverse.SECOND);
	BitmaskSet<TestUniverse> setOf2a = BitmaskSet.of(TestUniverse.FIRST, TestUniverse.THIRD);
	BitmaskSet<TestUniverse> setOf3 =
		BitmaskSet.of(TestUniverse.FIRST, TestUniverse.SECOND, TestUniverse.THIRD);

	BitmaskSet<TestAlternate> altOf0 = BitmaskSet.of();

	@Test
	public void testEmptiesDifferentTypesEqual() {
		// This portion verifies the behavior of stock Java collections
		assertEquals(intOf0, strOf0);

		// This portion verifies that BitmaskSet imitates that behavior
		assertEquals(setOf0, altOf0);
	}

	@Test
	public void testOf() {
		assertEquals(TestUniverse.class, setOf1.getUniverse());
		assertEquals(TestUniverse.class, setOf0.getUniverse());
	}

	@Test
	@SuppressWarnings("unlikely-arg-type") // Fair enough, Java. Fair enough. But it passes :)
	public void testContainsEmptyDifferentType() {
		// Check java behavior
		assertTrue(intOf3.containsAll(strOf0));
		// Check that BitmaskSet imitates it
		assertTrue(setOf2.containsAll(altOf0));
		assertTrue(setOf2.containsAll(strOf0));
	}

	@Test
	public void testOfHasSafeVarargs() {
		JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
		DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
		StringWriter writer = new StringWriter();
		PrintWriter out = new PrintWriter(writer);

		out.println("import " + Set.class.getCanonicalName() + ";");
		out.println("import " + BitmaskSet.class.getCanonicalName() + ";");
		out.println("import " + TestUniverse.class.getCanonicalName() + ";");
		out.println("import " + TestAlternate.class.getCanonicalName() + ";");
		out.println("");
		out.println("public class RequireFail {");
		out.println("    public static void main(String[] args) {");
		out.println("        Set<TestUniverse> testSet1 =");
		out.println("            BitmaskSet.of(TestUniverse.FIRST, TestAlternate.FIFTH);");
		out.println("    }");
		out.println("}");

		out.close();
		JavaFileObject file =
			new SimpleJavaFileObject(URI.create("string:///RequireFail.java"), Kind.SOURCE) {

				@Override
				public CharSequence getCharContent(boolean ignoreEncodingErrors)
						throws IOException {
					return writer.toString();
				}
			};
		Collection<JavaFileObject> units = Collections.singleton(file);

		JavaFileManager fmgr = new ForwardingJavaFileManager<StandardJavaFileManager>(
			compiler.getStandardFileManager(diagnostics, null, null)) {

			@Override
			public FileObject getFileForOutput(Location location, String packageName,
					String relativeName, FileObject sibling) throws IOException {
				Msg.debug(this, "Got request for output: '" + relativeName + "'");
				return null;
			}
		};

		CompilationTask task = compiler.getTask(null, fmgr, diagnostics,
			Arrays.asList("-classpath", System.getProperty("java.class.path")), null, units);
		assertFalse("Compilation should have failed", task.call());

		String firstMessage = null;
		for (Diagnostic<? extends JavaFileObject> diag : diagnostics.getDiagnostics()) {
			if (firstMessage == null) {
				firstMessage = diag.getLineNumber() + ":" + diag.getColumnNumber() + ": " +
					diag.getMessage(null);
			}
			if (diag.getMessage(null).contains(
				"method of in class ghidra.comm.util.BitmaskSet<E> cannot be applied to given types")) {
				return;
			}
		}
		fail("Unexpected compilation error, or no error: " + firstMessage);
	}

	@Test
	public void testCopy() {
		BitmaskSet<TestUniverse> test;

		test = new BitmaskSet<>(setOf0);
		assertEquals(0, test.getBitmask());

		test = new BitmaskSet<>(TestUniverse.class, setOf2);
		assertEquals(3, test.getBitmask());

		test = new BitmaskSet<>(TestUniverse.class, new HashSet<>(setOf0));
		assertEquals(0, test.getBitmask());

		test = new BitmaskSet<>(TestUniverse.class, new HashSet<>(setOf2));
		assertEquals(3, test.getBitmask());
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testEquality() {
		assertFalse(setOf2.equals("Some string"));

		assertTrue(setOf2.equals(setOf2));
		assertTrue(setOf2.equals(new HashSet<>(setOf2)));

		assertFalse(setOf2.equals(setOf1));
		assertFalse(setOf2.equals(new HashSet<>(setOf1)));

		assertFalse(setOf2.equals(setOf3));
		assertFalse(setOf2.equals(new HashSet<>(setOf3)));

		assertEquals(setOf2.hashCode(),
			new BitmaskSet<>(TestUniverse.class, new HashSet<>(setOf2)).hashCode());
	}

	@Test
	public void testSize() {
		assertTrue(setOf0.isEmpty());
		assertEquals(0, setOf0.size());
		assertEquals(1, setOf1.size());
		assertEquals(2, setOf2.size());

		assertEquals(0, new BitmaskSet<>(TestUniverse.class).size());
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testContains() {
		assertFalse(setOf0.contains(TestUniverse.FIRST));
		assertTrue(setOf1.contains(TestUniverse.FIRST));
		assertFalse(setOf1.contains(TestUniverse.SECOND));
		assertFalse(setOf1.contains("Some string"));
	}

	@Test
	public void testIterator() {
		Set<TestUniverse> test;
		Set<TestUniverse> exp;

		test = new HashSet<>(setOf2);
		exp = new HashSet<>(Arrays.asList(TestUniverse.FIRST, TestUniverse.SECOND));
		assertEquals(exp, test);

		test = new HashSet<>(setOf0);
		exp = new HashSet<>();
		assertEquals(exp, test);
	}

	@Test
	public void testArray() {
		TestUniverse[] arr;

		arr = setOf0.toArray(new TestUniverse[] {});
		assertEquals(0, arr.length);

		arr = setOf2.toArray(new TestUniverse[] {});
		assertEquals(2, arr.length);
		assertEquals(TestUniverse.FIRST, arr[0]);
		assertEquals(TestUniverse.SECOND, arr[1]);

		Object[] oarr = setOf2.toArray();
		assertEquals(2, oarr.length);
		assertEquals(TestUniverse.FIRST, oarr[0]);
		assertEquals(TestUniverse.SECOND, oarr[1]);
	}

	@Test
	public void testAdd() {
		BitmaskSet<TestUniverse> test = new BitmaskSet<>(setOf1);
		assertTrue(test.add(TestUniverse.SECOND));
		assertEquals(setOf2, test);

		assertFalse(test.add(TestUniverse.SECOND));
		assertEquals(setOf2, test);
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testRemove() {
		BitmaskSet<TestUniverse> test = new BitmaskSet<>(setOf2);
		assertTrue(test.remove(TestUniverse.SECOND));
		assertEquals(setOf1, test);

		assertFalse(test.remove(TestUniverse.SECOND));
		assertEquals(setOf1, test);

		assertFalse(test.remove("Some string"));
		assertEquals(setOf1, test);
	}

	@Test
	public void testContainsAll() {
		assertTrue(setOf0.containsAll(setOf0));
		assertFalse(setOf0.containsAll(setOf1));
		assertTrue(setOf0.containsAll(new HashSet<>()));
		assertFalse(setOf0.containsAll(new HashSet<>(setOf1)));

		assertTrue(setOf2.containsAll(setOf1));
		assertFalse(setOf1.containsAll(setOf2));
		assertTrue(setOf2.containsAll(new HashSet<>(setOf1)));
		assertFalse(setOf1.containsAll(new HashSet<>(setOf2)));
	}

	@Test
	public void testUnion() {
		BitmaskSet<TestUniverse> test = new BitmaskSet<>(setOf2);
		assertTrue(test.addAll(setOf2a));
		assertEquals(setOf3, test);
		assertFalse(test.addAll(setOf2a));
		assertEquals(setOf3, test);

		test = new BitmaskSet<>(setOf2);
		assertTrue(test.addAll(new HashSet<>(setOf2a)));
		assertEquals(setOf3, test);
		assertFalse(test.addAll(new HashSet<>(setOf2a)));
		assertEquals(setOf3, test);

		test = new BitmaskSet<>(setOf0);
		assertFalse(test.addAll(setOf0));
		assertEquals(setOf0, test);
		assertFalse(test.addAll(new HashSet<>(setOf0)));
		assertEquals(setOf0, test);

		test = new BitmaskSet<>(setOf0);
		assertTrue(test.addAll(setOf1));
		assertEquals(setOf1, test);
	}

	@Test
	public void testIntersection() {
		BitmaskSet<TestUniverse> test = new BitmaskSet<>(setOf2);
		assertTrue(test.retainAll(setOf2a));
		assertEquals(setOf1, test);
		assertFalse(test.retainAll(setOf2a));
		assertEquals(setOf1, test);

		test = new BitmaskSet<>(setOf2);
		assertTrue(test.retainAll(new HashSet<>(setOf2a)));
		assertEquals(setOf1, test);
		assertFalse(test.retainAll(new HashSet<>(setOf2a)));
		assertEquals(setOf1, test);

		test = new BitmaskSet<>(setOf2);
		assertTrue(test.retainAll(new HashSet<>()));
		assertEquals(setOf0, test);
		assertFalse(test.retainAll(new HashSet<>()));
		assertEquals(setOf0, test);

		test = new BitmaskSet<>(setOf2);
		Set<Object> temp = new HashSet<>();
		temp.addAll(setOf2a);
		temp.add("Some string");
		assertTrue(test.retainAll(temp));
		assertEquals(setOf1, test);
		assertFalse(test.retainAll(temp));
		assertEquals(setOf1, test);
	}

	@Test
	public void testSubtraction() {
		BitmaskSet<TestUniverse> exp = BitmaskSet.of(TestUniverse.SECOND);

		BitmaskSet<TestUniverse> test = new BitmaskSet<>(setOf2);
		assertTrue(test.removeAll(setOf2a));
		assertEquals(exp, test);
		assertFalse(test.removeAll(setOf2a));
		assertEquals(exp, test);

		test = new BitmaskSet<>(setOf2);
		assertTrue(test.removeAll(new HashSet<>(setOf2a)));
		assertEquals(exp, test);
		assertFalse(test.removeAll(new HashSet<>(setOf2a)));
		assertEquals(exp, test);

		test = new BitmaskSet<>(setOf2);
		assertFalse(test.removeAll(new HashSet<>()));
		assertEquals(setOf2, test);

		test = new BitmaskSet<>(setOf2);
		Set<Object> temp = new HashSet<>();
		temp.addAll(setOf2a);
		temp.add("Some string");
		assertTrue(test.removeAll(temp));
		assertEquals(exp, test);
		assertFalse(test.removeAll(temp));
		assertEquals(exp, test);
	}

	@Test
	public void testClear() {
		BitmaskSet<TestUniverse> test = new BitmaskSet<>(setOf2);
		test.clear();
		assertEquals(setOf0, test);
	}

	@Test
	public void testToString() {
		assertEquals("[]", setOf0.toString());
		assertEquals("[FIRST]", setOf1.toString());
		assertEquals("[FIRST, SECOND]", setOf2.toString());
	}

	@Test
	public void testBitmask() {
		assertEquals(0, setOf0.getBitmask());
		assertEquals(1, setOf1.getBitmask());
		assertEquals(3, setOf2.getBitmask());
		assertEquals(7, setOf3.getBitmask());

		BitmaskSet<TestUniverse> test = new BitmaskSet<>(TestUniverse.class);
		test.setBitmask(5);
		assertEquals(test, BitmaskSet.of(TestUniverse.FIRST, TestUniverse.THIRD));
	}
}
