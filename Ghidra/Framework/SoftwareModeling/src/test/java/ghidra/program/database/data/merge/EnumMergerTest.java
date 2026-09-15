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
package ghidra.program.database.data.merge;

import static org.junit.Assert.*;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.util.UniversalIdGenerator;

public class EnumMergerTest extends AbstractGenericTest {
	private StandAloneDataTypeManager dataTypeManager;
	private int txId;

	@Before
	public void setUp() throws Exception {
		UniversalIdGenerator.initialize();
		dataTypeManager = new StandAloneDataTypeManager("Test");
		txId = dataTypeManager.startTransaction("Test");
	}

	@After
	public void tearDown() {
		dataTypeManager.endTransaction(txId, false);
	}

	@Test
	public void testSimpleMerge() throws Exception {
		Enum enum1 = new EnumBuilder("A", 8)
				.entry("joe", 5)
				.buildDb();

		Enum enum2 = new EnumBuilder("B", 8)
				.entry("bob", 10)
				.buildDb();

		Enum expected = new EnumBuilder("A", 8)
				.entry("bob", 10)
				.entry("joe", 5)
				.build();

		EnumMerger merger = new EnumMerger(enum1, enum2);
		Enum result = merger.merge();

		assertEnumEquals(expected, result);
	}

	@Test
	public void testSameValueForDifferentNames() throws Exception {
		Enum enum1 = new EnumBuilder("A", 8)
				.entry("joe", 10)
				.buildDb();

		Enum enum2 = new EnumBuilder("B", 8)
				.entry("bob", 10)
				.buildDb();

		Enum expected = new EnumBuilder("A", 8)
				.entry("bob", 10)
				.entry("joe", 10)
				.build();

		EnumMerger merger = new EnumMerger(enum1, enum2);
		Enum result = merger.merge();

		assertEnumEquals(expected, result);
	}

	@Test
	public void testValueCollision() throws Exception {
		Enum enum1 = new EnumBuilder("A", 8)
				.entry("joe", 5)
				.buildDb();

		Enum enum2 = new EnumBuilder("B", 8)
				.entry("joe", 10)
				.buildDb();

		EnumMerger merger = new EnumMerger(enum1, enum2);

		try {
			merger.merge();
			fail("Expected exception due to value conflict");
		}
		catch (DataTypeMergeException e) {
			assertEquals("Enums have different values for name \"joe\". 5 and 10", e.getMessage());
		}
	}

	@Test
	public void testSizeDifference() throws Exception {
		Enum enum1 = new EnumBuilder("A", 4)
				.entry("joe", 5)
				.buildDb();

		Enum enum2 = new EnumBuilder("B", 8)
				.entry("bob", 10)
				.buildDb();

		Enum expected = new EnumBuilder("A", 8)
				.entry("joe", 5)
				.entry("bob", 10)
				.build();

		EnumMerger merger = new EnumMerger(enum1, enum2);
		Enum result = merger.merge();

		assertEnumEquals(expected, result);
	}

	@Test
	public void testSignedDifference() throws Exception {
		Enum enum1 = new EnumBuilder("A", 1)
				.entry("joe", -5)
				.buildDb();

		Enum enum2 = new EnumBuilder("B", 1)
				.entry("bob", 255)
				.buildDb();

		EnumMerger merger = new EnumMerger(enum1, enum2);
		try {
			merger.merge();
			fail("Expected exception due to signedness conflict");
		}
		catch (DataTypeMergeException e) {
			assertEquals(
				"Enum conflict: one enum has negative values: one has large unsigned values",
				e.getMessage());
		}
	}

	@Test
	public void testCommentMerge() throws Exception {
		Enum enum1 = new EnumBuilder("A", 8)
				.entry("aaa", 1, "hey")
				.entry("bbb", 2)
				.entry("ccc", 3, "hey")
				.entry("ddd", 4, "hey")
				.buildDb();

		Enum enum2 = new EnumBuilder("B", 8)
				.entry("aaa", 1, "hey")
				.entry("bbb", 2, "hey")
				.entry("ccc", 3)
				.entry("ddd", 4, "there")
				.buildDb();

		Enum expected = new EnumBuilder("A", 8)
				.entry("aaa", 1, "hey")
				.entry("bbb", 2, "hey")
				.entry("ccc", 3, "hey")
				.entry("ddd", 4, "hey there")
				.build();

		EnumMerger merger = new EnumMerger(enum1, enum2);
		Enum result = merger.merge();

		assertEnumEquals(expected, result);
	}

	private void assertEnumEquals(Enum expected, Enum actual) {
		if (expected.equals(actual)) {
			return;
		}
		String es = expected.toString();
		String as = actual.toString();
		String msg = "\nExpected: \n%s\nActual: \n%s".formatted(es, as);
		fail(msg);
	}

	private class EnumBuilder {
		private Enum result;

		public EnumBuilder(String name, int size) {
			result = new EnumDataType(CategoryPath.ROOT, name, size, dataTypeManager);
		}

		public EnumBuilder entry(String name, long value) {
			result.add(name, value);
			return this;
		}

		public EnumBuilder entry(String name, long value, String comment) {
			result.add(name, value, comment);
			return this;
		}

		public Enum build() {
			return result;
		}

		public Enum buildDb() {
			return (Enum) dataTypeManager.resolve(result, null);
		}
	}

}
