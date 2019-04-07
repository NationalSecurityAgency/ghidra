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
package ghidra.program.model.address;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import generic.test.AbstractGenericTest;

import org.junit.Before;
import org.junit.Test;

public class AddressSetMappingTest extends AbstractGenericTest {
	private AddressSpace space = new GenericAddressSpace("xx", 32, AddressSpace.TYPE_RAM, 0);
	private AddressSet set;
	private AddressSetMapping mapping;

	@Before
	public void setUp() throws Exception {
		set = new AddressSet();
		set.add(addr(10), addr(19));
		set.add(addr(30), addr(39));
		set.add(addr(50), addr(59));
		set.add(addr(70), addr(79));
		mapping = new AddressSetMapping(set);
	}

	@Test
	public void testStart() {
		assertEquals(addr(10), mapping.getAddress(0));
	}

	@Test
	public void testEnd() {
		assertEquals(addr(79), mapping.getAddress(39));
	}

	@Test
	public void testBadIndexes() {
		assertNull(mapping.getAddress(-1));
		assertNull(mapping.getAddress(40));
	}

	@Test
	public void testSequentialAccess() {
		AddressIterator addressIterator = set.getAddresses(true);
		for (int i = 0; i < 40; i++) {
			assertEquals(addressIterator.next(), mapping.getAddress(i));
		}
	}

	@Test
	public void testRandomAccess() {
		assertEquals(addr(50), mapping.getAddress(20));
		assertEquals(addr(10), mapping.getAddress(0));
		assertEquals(addr(59), mapping.getAddress(29));
		assertEquals(addr(35), mapping.getAddress(15));
	}

	private Address addr(int offset) {
		return new GenericAddress(space, offset);
	}

}
