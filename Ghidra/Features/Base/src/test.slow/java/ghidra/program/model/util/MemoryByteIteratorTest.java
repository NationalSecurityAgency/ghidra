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
package ghidra.program.model.util;

import static org.junit.Assert.*;

import java.util.Spliterators;
import java.util.stream.StreamSupport;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class MemoryByteIteratorTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private Program program;
	private AddressFactory af;

	private Address addr(String a) {
		return af.getAddress(a);
	}

	private Program buildProgram(String name, String languageID) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(name, languageID);
		builder.createMemory("test1", "0x1001000", 0x6600);
		builder.setBytes("0x1001000", "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F");
		builder.setBytes("0x1001140", "DE AD BE EF");
		builder.setBytes("0x1004ffe", "EE FF");  // these values are right before the buffer boundary
		builder.setBytes("0x1005000", "AA BB CC DD"); // these values are right after the buffer boundary
		return builder.getProgram();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		program = buildProgram("notepad", ProgramBuilder._TOY);
		af = program.getAddressFactory();
	}

	@After
	public void tearDown() {
		env.release(program);
		env.dispose();
	}

	@Test
	public void testEmptyRange() {
		MemoryByteIterator it = new MemoryByteIterator(program.getMemory(), new AddressSet());
		long count =
			StreamSupport.stream(Spliterators.spliteratorUnknownSize(it, 0), false).count();
		assertEquals(0, count);
	}

	@Test
	public void test1Byte() {
		MemoryByteIterator it =
			new MemoryByteIterator(program.getMemory(), new AddressSet(addr("0x1001000")));
		long count =
			StreamSupport.stream(Spliterators.spliteratorUnknownSize(it, 0), false).count();
		assertEquals(1, count);
	}

	@Test
	public void test2Byte() {
		MemoryByteIterator it = new MemoryByteIterator(program.getMemory(),
			new AddressSet(addr("0x1001000"), addr("0x1001001")));
		long count =
			StreamSupport.stream(Spliterators.spliteratorUnknownSize(it, 0), false).count();
		assertEquals(2, count);
	}

	@Test
	public void testIterator() throws Exception {
		AddressSet set = new AddressSet(addr("0x1000000"), addr("0x100100f"));
		set.addRange(addr("0x1001140"), addr("0x1001144"));
		MemoryByteIterator it = new MemoryByteIterator(program.getMemory(), set);
		int total = 0;
		int count = 0;
		while (it.hasNext()) {
			byte b = it.next();
			count++;
			total += b;
		}
		assertEquals(21, count);
		assertEquals(-80, total);
	}

	@Test
	public void testIterator2() throws Exception {
		AddressSet set = new AddressSet(addr("0x1001000"), addr("0x10075ff"));
		MemoryByteIterator it = new MemoryByteIterator(program.getMemory(), set);
		long count =
			StreamSupport.stream(Spliterators.spliteratorUnknownSize(it, 0), false).count();
		assertEquals(0x6600, count);
	}

	@Test
	public void testReadBytesNearBufferBoundary() {
		AddressSet set = new AddressSet(addr("0x1001000"), addr("0x10075ff"));
		MemoryByteIterator it = new MemoryByteIterator(program.getMemory(), set);
		int index = 0;
		int testcount = 0;
		while (it.hasNext()) {
			int b = Byte.toUnsignedInt(it.nextByte());
			switch (index) {
				//@formatter:off
				case MemoryByteIterator.MAX_BUF_SIZE - 2: assertEquals(0xee, b); testcount++; break;
				case MemoryByteIterator.MAX_BUF_SIZE - 1: assertEquals(0xff, b); testcount++; break;
				case MemoryByteIterator.MAX_BUF_SIZE:     assertEquals(0xaa, b); testcount++; break;
				case MemoryByteIterator.MAX_BUF_SIZE + 1: assertEquals(0xbb, b); testcount++; break;
				//@formatter:on
			}
			index++;
		}
		assertEquals(4, testcount);
	}

	@Test
	public void testOOBAddrRange() {
		// Test that invalid / unmapped addresses cause the iterator to signal end-of-iteration
		AddressSet set = new AddressSet(addr("0x10075ff"), addr("0x1007700"));
		MemoryByteIterator it = new MemoryByteIterator(program.getMemory(), set);
		long count =
			StreamSupport.stream(Spliterators.spliteratorUnknownSize(it, 0), false).count();
		assertEquals(1, count);
	}

	@Test
	public void testOOBAddrRange2() {
		// Test that invalid / unmapped addresses cause the iterator to signal end-of-iteration
		AddressSet set = new AddressSet(addr("0x1007600"), addr("0x1007700"));
		MemoryByteIterator it = new MemoryByteIterator(program.getMemory(), set);
		long count =
			StreamSupport.stream(Spliterators.spliteratorUnknownSize(it, 0), false).count();
		assertEquals(0, count);
	}
}
