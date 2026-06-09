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
package ghidra.util.bytesearch;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.XmlPullParser;

public class MemoryBytePatternSearcherTest extends AbstractGhidraHeadlessIntegrationTest {

	private ProgramBuilder builder;
	private ProgramDB program;
	List<AddressMatch<Pattern>> results = new ArrayList<>();
	private MatchAction[] matchActions;

	@Before
	public void setup() throws Exception {
		program = buildProgram();
		matchActions = new MatchAction[1];
		matchActions[0] = new TestMatchAction();
	}

	@Test
	public void testMatchesDontSpanBlocks() throws Exception {
		builder.setString("0x1001010", "Hello");
		builder.setString("0x10010ff", "Hello");	// crosses block boundary, shouldn't be found
		builder.setString("0x1001520", "There");
		TestPattern p1 = new TestPattern("Hello");
		TestPattern p2 = new TestPattern("There");
		MemoryBytePatternSearcher searcher = createSearcher(p1, p2);

		searcher.search(program, null, TaskMonitor.DUMMY);

		assertEquals(2, results.size());
		assertMatch(results.get(0), addr(0x1001010));
		assertMatch(results.get(1), addr(0x1001520));
	}

	@Test
	public void testMatchInAddressSet() throws Exception {
		builder.setString("0x1001010", "Hello");
		TestPattern p1 = new TestPattern("Hello");
		MemoryBytePatternSearcher searcher = createSearcher(p1);
		AddressSet searchSet = addrSet(0x1001005, 0x1001030);

		searcher.search(program, searchSet, TaskMonitor.DUMMY);

		assertEquals(1, results.size());
		assertMatch(results.get(0), addr(0x1001010));
	}

	@Test
	public void testMatchStartsOutsideRange() throws Exception {
		builder.setString("0x1001010", "Hello");
		TestPattern p1 = new TestPattern("Hello");
		MemoryBytePatternSearcher searcher = createSearcher(p1);
		AddressSet searchSet = addrSet(0x1001011, 0x1001030);

		searcher.search(program, searchSet, TaskMonitor.DUMMY);

		assertTrue(results.isEmpty());
	}

	@Test
	public void testMatchStartsInRangeAndExtendsOut() throws Exception {
		builder.setString("0x1001010", "Hello");
		TestPattern p1 = new TestPattern("Hello");
		MemoryBytePatternSearcher searcher = createSearcher(p1);
		AddressSet searchSet = addrSet(0x1001010, 0x1001012);

		searcher.search(program, searchSet, TaskMonitor.DUMMY);

		assertEquals(1, results.size());
		assertMatch(results.get(0), addr(0x1001010));
	}

	@Test
	public void testPreSequencePattern() throws Exception {
		builder.setString("0x1001010", "HelloThere");
		TestPattern p1 = new TestPattern("HelloThere", 5);
		MemoryBytePatternSearcher searcher = createSearcher(p1);
		AddressSet searchSet = addrSet(0x1001000, 0x1001040);

		searcher.search(program, searchSet, TaskMonitor.DUMMY);
		assertEquals(1, results.size());
		assertMatch(results.get(0), addr(0x1001015));
	}

	@Test
	public void testPreSequencePattern_preStartsBeforeRange() throws Exception {
		builder.setString("0x1001010", "HelloThere");
		TestPattern p1 = new TestPattern("HelloThere", 5);
		MemoryBytePatternSearcher searcher = createSearcher(p1);
		AddressSet searchSet = addrSet(0x1001012, 0x1001040);

		searcher.search(program, searchSet, TaskMonitor.DUMMY);
		assertEquals(1, results.size());
		assertMatch(results.get(0), addr(0x1001015));
	}

	@Test
	public void testPreSequencePattern_primaryStartsBeforeRange() throws Exception {
		builder.setString("0x1001010", "HelloThere");
		TestPattern p1 = new TestPattern("HelloThere", 5);
		MemoryBytePatternSearcher searcher = createSearcher(p1);
		AddressSet searchSet = addrSet(0x1001016, 0x1001040);

		searcher.search(program, searchSet, TaskMonitor.DUMMY);
		assertTrue(results.isEmpty());
	}

	@Test
	public void testSearchExecuteBlocksOnly() throws Exception {
		MemoryBlock block = builder.createMemory("execute", "0x2000000", 0x100);
		builder.setExecute(block, true);

		builder.setString("0x1001010", "Hello");
		builder.setString("0x2000010", "Hello");
		TestPattern p1 = new TestPattern("Hello");
		MemoryBytePatternSearcher searcher = createSearcher(p1);
		searcher.setSearchExecutableOnly(true);
		searcher.searchAll(program, TaskMonitor.DUMMY);

		assertEquals(1, results.size());
		assertMatch(results.get(0), addr(0x2000010));
	}

	@Test
	public void testAddPatternsLater() throws Exception {
		builder.setString("0x1001010", "Hello");
		builder.setString("0x1001030", "There");
		TestPattern p1 = new TestPattern("Hello");
		MemoryBytePatternSearcher searcher = createSearcher(p1);
		searcher.searchAll(program, TaskMonitor.DUMMY);

		assertEquals(1, results.size());
		assertMatch(results.get(0), addr(0x1001010));

		results.clear();
		searcher.addPattern(new TestPattern("There"));
		searcher.searchAll(program, TaskMonitor.DUMMY);
		assertEquals(2, results.size());
		assertMatch(results.get(0), addr(0x1001010));
		assertMatch(results.get(1), addr(0x1001030));
	}

	@Test
	public void testMappedBlocks() throws Exception {
		builder.createMappedMemory("mapped", "0x2000000", 0x10000, "0x1000000");

		builder.setString("0x1001100", "Hello");
		builder.setString("0x1001510", "Hello");
		TestPattern p1 = new TestPattern("Hello");
		MemoryBytePatternSearcher searcher = createSearcher(p1);
		searcher.searchAll(program, TaskMonitor.DUMMY);
		assertEquals(4, results.size());
		assertMatch(results.get(0), addr(0x1001100));
		assertMatch(results.get(1), addr(0x1001510));
		assertMatch(results.get(2), addr(0x2001100));
		assertMatch(results.get(3), addr(0x2001510));

	}

	private Address addr(long offset) {
		return builder.addr(offset);
	}

	private AddressSet addrSet(long start, long end) {
		return new AddressSet(addr(start), addr(end));
	}

	private ProgramDB buildProgram() throws Exception {
		builder = new ProgramBuilder("Program1", ProgramBuilder._TOY, this);

		builder.createMemory("b1", "0x1001000", 0x100);
		builder.createMemory("b2", "0x1001100", 0x100);
		builder.createMemory("b3", "0x1001500", 0x100);
		CategoryPath miscPath = new CategoryPath("/MISC");
		builder.addCategory(miscPath);
		return builder.getProgram();
	}

	private MemoryBytePatternSearcher createSearcher(Pattern... patterns) {
		List<Pattern> patternList = Arrays.asList(patterns);
		return new MemoryBytePatternSearcher("Test", patternList);
	}

	private void assertMatch(AddressMatch<Pattern> addressMatch, Address addr) {
		assertEquals("Match address", addr, addressMatch.getAddress());
	}

	private class TestPattern extends Pattern {

		private String inputString;
		private int preSequenceLength;

		public TestPattern(String inputString) {
			this(inputString, 0);
		}

		public TestPattern(String inputString, int preSequenceLength) {
			super(new DittedBitSequence(getBytes(inputString), getMask(inputString)),
				preSequenceLength, new PostRule[0], matchActions);
			this.inputString = inputString;
			this.preSequenceLength = preSequenceLength;
		}

		private static byte[] getMask(String inputString) {
			byte[] mask = new byte[inputString.length()];
			for (int i = 0; i < inputString.length(); i++) {
				if (inputString.charAt(i) == '.') {
					mask[i] = 0;
				}
				else {
					mask[i] = (byte) 0xff;
				}
			}
			return mask;
		}

		private static byte[] getBytes(String inputString) {
			byte[] bytes = inputString.getBytes();
			for (int i = 0; i < inputString.length(); i++) {
				if (inputString.charAt(i) == '.') {
					bytes[i] = 0;
				}
			}
			return bytes;
		}

		@Override
		public String toString() {
			return inputString;
		}

		@Override
		public int getPreSequenceLength() {
			return preSequenceLength;
		}

	}

	private class TestMatchAction implements MatchAction {

		@Override
		public void apply(Program program, Address addr, Match<Pattern> match) {
			results.add(new AddressMatch<Pattern>(match.getPattern(), match.getStart(),
				match.getLength(), addr));
		}

		@Override
		public void restoreXml(XmlPullParser parser) {
			// not used
		}

	}

}
