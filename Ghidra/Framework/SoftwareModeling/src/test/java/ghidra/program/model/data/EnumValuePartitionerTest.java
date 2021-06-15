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
package ghidra.program.model.data;

import static org.junit.Assert.*;

import java.util.List;
import java.util.Set;

import org.junit.Test;

import generic.test.AbstractGTest;

public class EnumValuePartitionerTest extends AbstractGTest {

	@Test
	public void testDisjointValues() {
		List<BitGroup> list = EnumValuePartitioner.partition(new long[] { 1, 2, 4, 8 }, 1);
		assertEquals(5, list.size());
	}

	@Test
	public void testAllOverlappingValues() {
		List<BitGroup> list = EnumValuePartitioner.partition(new long[] { 1, 2, 4, 8, 15 }, 1);
		assertEquals(2, list.size());
		BitGroup group = list.get(0);
		assertEquals(15, group.getMask());
		Set<Long> values = group.getValues();
		assertEquals(5, values.size());
		assertTrue(values.contains(1L));
		assertTrue(values.contains(2L));
		assertTrue(values.contains(4L));
		assertTrue(values.contains(8L));
		assertTrue(values.contains(15L));
	}

	@Test
	public void testSomeOverlappingValues() {
		List<BitGroup> list = EnumValuePartitioner.partition(new long[] { 1, 2, 4, 8, 6 }, 1);
		assertEquals(4, list.size());
		assertEquals(1, list.get(0).getMask());
		assertEquals(8, list.get(1).getMask());
		assertEquals(6, list.get(2).getMask());
	}
}
