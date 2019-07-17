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
/*
 * Created on Jul 30, 2003
 *
 * To change the template for this generated file go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package ghidra.app.plugin.core.codebrowser;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.program.model.address.*;

public class AddressIndexMapWithRemovedRangesTest extends AbstractGenericTest {
	private AddressSpace space;
	private AddressIndexMap map;

	/*
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {
		space = new GenericAddressSpace("Test", 32, AddressSpace.TYPE_RAM, 0);
		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(399));
		set.addRange(addr(500), addr(999));
		map = new AddressIndexMap(set);

	}

	private Address addr(int offset) {
		return space.getAddress(offset);
	}

	@Test
	public void testSizeAfterRemove() {
		assertEquals(900L, map.getIndexCount().longValue());

		removeAddressRange(200, 299);
		removeAddressRange(600, 699);

		assertEquals(700L, map.getIndexCount().longValue());
	}

	@Test
	public void testIndexMappingAfterRemove() {
		removeAddressRange(200, 299);

		assertEquals(addr(199), getAddress(199));
		assertEquals(addr(300), getAddress(200));
	}

	@Test
	public void testGapAddressWithRemovedRange() {
		assertEquals(false, map.isGapAddress(addr(300)));
		removeAddressRange(200, 299);  // this should NOT cause a gap address
		assertEquals(false, map.isGapAddress(addr(300)));
	}

	@Test
	public void testGetMinimumViewableGapSize() {
		assertEquals(AddressIndexMap.DEFAULT_UNVIEWABLE_GAP_SIZE, map.getMiniumUnviewableGapSize());

		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(10000));
		map = new AddressIndexMap(set);

		assertEquals(100, map.getMiniumUnviewableGapSize().intValue());

	}

	@Test
	public void testReset() {
		assertEquals(900, map.getIndexCount().intValue());
		removeAddressRange(200, 299);
		assertEquals(800, map.getIndexCount().intValue());
		map.reset();
		assertEquals(900, map.getIndexCount().intValue());
	}

	@Test
	public void testGetAddressSet() {
		removeAddressRange(200, 299);
		assertTrue(map.getOriginalAddressSet().contains(addr(200)));
		assertTrue(map.getOriginalAddressSet().contains(addr(299)));
		assertTrue(!map.getIndexedAddressSet().contains(addr(200)));
		assertTrue(!map.getIndexedAddressSet().contains(addr(299)));
	}

	private Address getAddress(int index) {
		return map.getAddress(BigInteger.valueOf(index));
	}

	private void removeAddressRange(int start, int end) {
		AddressSet removeSet = new AddressSet();
		removeSet.addRange(addr(start), addr(end));
		map.removeUnviewableAddressRanges(removeSet);
	}

}
