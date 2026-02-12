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
import ghidra.util.UniversalIdGenerator;

public class UnionMergerTest extends AbstractGenericTest {
	private DataType wordDt;
	private DataType dwordDt;
	private IntegerDataType intDt;
	private StandAloneDataTypeManager dataTypeManager;
	private int txId;

	@Before
	public void setUp() throws Exception {
		UniversalIdGenerator.initialize();
		wordDt = new WordDataType();
		dwordDt = new DWordDataType();
		intDt = new IntegerDataType();
		dataTypeManager = new StandAloneDataTypeManager("Test");
		txId = dataTypeManager.startTransaction("Test");
	}

	@After
	public void tearDown() {
		dataTypeManager.endTransaction(txId, false);
	}

	@Test
	public void testSimpleMerge() throws Exception {
		Union union1 = new UnionBuilder("A", 8)
				.entry(wordDt, "joe")
				.buildDb();

		Union union2 = new UnionBuilder("B", 8)
				.entry(wordDt, "bob")
				.buildDb();

		Union expected = new UnionBuilder("A", 8)
				.entry(wordDt, "joe")
				.entry(wordDt, "bob")
				.build();

		UnionMerger merger = new UnionMerger(union1, union2);
		Union result = merger.merge();

		assertUnionEquals(expected, result);
	}

	@Test
	public void testMergeWithAdditionalEntry() throws Exception {
		Union union1 = new UnionBuilder("A", 8)
				.entry(wordDt, "joe")
				.buildDb();

		Union union2 = new UnionBuilder("B", 8)
				.entry(wordDt, "bob")
				.entry(wordDt, "joe", "hey")
				.buildDb();

		Union expected = new UnionBuilder("A", 8)
				.entry(wordDt, "joe", "hey")
				.entry(wordDt, "bob")
				.build();

		UnionMerger merger = new UnionMerger(union1, union2);
		Union result = merger.merge();

		assertUnionEquals(expected, result);
	}

	@Test
	public void testConflictEntry() throws Exception {
		Union union1 = new UnionBuilder("A", 8)
				.entry(wordDt, "joe")
				.buildDb();

		Union union2 = new UnionBuilder("B", 8)
				.entry(dwordDt, "joe")
				.buildDb();

		UnionMerger merger = new UnionMerger(union1, union2);

		try {
			merger.merge();
			fail("Expected exception");
		}
		catch (DataTypeMergeException e) {
			assertEquals("Unions have conflicting components named joe", e.getMessage());
		}
	}

	@Test
	public void testMergeComments() throws Exception {
		Union union1 = new UnionBuilder("A", 8)
				.entry(wordDt, "aaa")
				.entry(wordDt, "bbb", "hey")
				.entry(wordDt, "ccc", "hey")
				.entry(wordDt, "ddd", "hey")
				.buildDb();

		Union union2 = new UnionBuilder("B", 8)
				.entry(wordDt, "aaa", "hey")
				.entry(wordDt, "bbb")
				.entry(wordDt, "ccc", "hey")
				.entry(wordDt, "ddd", "there")
				.buildDb();

		Union expected = new UnionBuilder("A", 8)
				.entry(wordDt, "aaa", "hey")
				.entry(wordDt, "bbb", "hey")
				.entry(wordDt, "ccc", "hey")
				.entry(wordDt, "ddd", "hey there")
				.build();

		UnionMerger merger = new UnionMerger(union1, union2);
		Union result = merger.merge();

		assertUnionEquals(expected, result);
	}

	@Test
	public void testUpgradeFromUndefined4ToDWord() throws DataTypeMergeException {
		Union union1 = new UnionBuilder("A", 8)
				.entry(new Undefined4DataType(), "joe")
				.buildDb();

		Union union2 = new UnionBuilder("B", 8)
				.entry(intDt, "joe")
				.buildDb();

		Union expected = new UnionBuilder("A", 8)
				.entry(intDt, "joe")
				.build();

		UnionMerger merger = new UnionMerger(union1, union2);

		Union result = merger.merge();
		assertUnionEquals(expected, result);
		assertEquals("Merging \"undefined4\" and \"int to \"int\" for member \"joe\".",
			merger.getWarnings().get(0));
	}

	@Test
	public void testUpgradeFromUndefined4ToDWord_otherDirection() throws DataTypeMergeException {
		Union union1 = new UnionBuilder("A", 8)
				.entry(intDt, "joe")
				.buildDb();

		Union union2 = new UnionBuilder("B", 8)
				.entry(new Undefined4DataType(), "joe")
				.buildDb();

		Union expected = new UnionBuilder("A", 8)
				.entry(intDt, "joe")
				.build();

		UnionMerger merger = new UnionMerger(union1, union2);

		Union result = merger.merge();
		assertUnionEquals(expected, result);
		assertEquals("Merging \"int\" and \"undefined4 to \"int\" for member \"joe\".",
			merger.getWarnings().get(0));
	}

	@Test
	public void testUpgradeFromintToPointer() throws DataTypeMergeException {
		Union union1 = new UnionBuilder("A", 8)
				.entry(intDt, "joe")
				.buildDb();

		Union union2 = new UnionBuilder("B", 8)
				.entry(new PointerDataType(wordDt), "joe")
				.buildDb();

		Union expected = new UnionBuilder("A", 8)
				.entry(new PointerDataType(wordDt), "joe")
				.build();

		UnionMerger merger = new UnionMerger(union1, union2);

		Union result = merger.merge();
		assertUnionEquals(expected, result);
		assertEquals("Merging \"int\" and \"word * to \"word *\" for member \"joe\".",
			merger.getWarnings().get(0));
	}

	private void assertUnionEquals(Union expected, Union actual) {
		if (expected.equals(actual)) {
			return;
		}
		String es = expected.toString();
		String as = actual.toString();
		String msg = "\nExpected: \n%s\nActual: \n%s".formatted(es, as);
		fail(msg);
	}

	private class UnionBuilder {
		private Union result;

		public UnionBuilder(String name, int size) {
			result = new UnionDataType(null, name, dataTypeManager);
		}

		public UnionBuilder entry(DataType dt, String name) {
			result.add(dt, -1, name, null);
			return this;
		}

		public UnionBuilder entry(DataType dt, String name, String comment) {
			result.add(dt, -1, name, comment);
			return this;
		}

		public Union build() {
			return result;
		}

		public Union buildDb() {
			return (Union) dataTypeManager.resolve(result, null);
		}
	}

}
