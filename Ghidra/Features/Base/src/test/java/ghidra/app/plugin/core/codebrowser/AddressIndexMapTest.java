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

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.fieldpanel.support.FieldRange;
import docking.widgets.fieldpanel.support.FieldSelection;
import generic.test.AbstractGenericTest;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.program.model.address.*;

public class AddressIndexMapTest extends AbstractGenericTest {
	private AddressSpace space;
	private AddressIndexMap map;

	/*
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {
		space = new GenericAddressSpace("Test", 32, AddressSpace.TYPE_RAM, 0);
		AddressSet set = new AddressSet();
		set.addRange(addr(100), addr(109));
		set.addRange(addr(200), addr(209));
		set.addRange(addr(300), addr(309));
		map = new AddressIndexMap(set);
	}

	private Address addr(int offset) {
		return space.getAddress(offset);
	}

	@Test
	public void testGetAddress() {
		assertEquals(addr(100), map.getAddress(BigInteger.valueOf(0)));
		assertEquals(addr(101), map.getAddress(BigInteger.valueOf(1)));
		assertEquals(addr(109), map.getAddress(BigInteger.valueOf(9)));
		assertEquals(addr(200), map.getAddress(BigInteger.valueOf(10)));
		assertEquals(addr(209), map.getAddress(BigInteger.valueOf(19)));
		assertEquals(addr(300), map.getAddress(BigInteger.valueOf(20)));
		assertEquals(addr(309), map.getAddress(BigInteger.valueOf(29)));
		assertNull(map.getAddress(BigInteger.valueOf(30)));
	}

	@Test
	public void testGetIndex() {
		assertEquals(null, map.getIndex(addr(0)));
		assertEquals(0, map.getIndex(addr(100)).intValue());
		assertEquals(1, map.getIndex(addr(101)).intValue());
		assertEquals(9, map.getIndex(addr(109)).intValue());
		assertEquals(null, map.getIndex(addr(110)));
		assertEquals(10, map.getIndex(addr(200)).intValue());
		assertEquals(11, map.getIndex(addr(201)).intValue());
		assertEquals(29, map.getIndex(addr(309)).intValue());
		assertEquals(null, map.getIndex(addr(310)));

	}

	@Test
	public void testEmptyMap() {
		map = new AddressIndexMap();
		assertEquals(0, map.getIndexCount().intValue());

		assertNull(map.getAddress(BigInteger.ZERO));
		assertEquals(null, map.getIndex(addr(100)));
	}

	@Test
	public void testIsGapIndex() {
		assertEquals(false, map.isGapIndex(BigInteger.valueOf(0)));
		assertEquals(false, map.isGapIndex(BigInteger.valueOf(5)));
		assertEquals(true, map.isGapIndex(BigInteger.valueOf(10)));
	}

	@Test
	public void testIsGapIndexAfterAccessingValue() {
		// this is  mainly about getting all code paths tested. By accessing values first,
		// we are exercising the code that tries to use optimized cached ranges.
		map.getAddress(BigInteger.valueOf(5));
		assertEquals(false, map.isGapIndex(BigInteger.valueOf(5)));
		map.getAddress(BigInteger.valueOf(20));
		assertEquals(false, map.isGapIndex(BigInteger.valueOf(5)));
	}

	@Test
	public void testIsGapIndexWithNull() {
		assertEquals(false, map.isGapAddress(null));
	}

	@Test
	public void testIsGapAddressOnMinAddress() {
		assertEquals(false, map.isGapAddress(addr(100)));
	}

	@Test
	public void testNegativeIndex() {
		assertNull(map.getAddress(BigInteger.valueOf(-1)));
	}

	@Test
	public void testNullIndex() {
		assertNull(map.getAddress(null));
	}

	@Test
	public void testGetAddressAfterCacheHit() {
		map.getAddress(BigInteger.valueOf(15));  // forcing use of cache check in next call
		assertEquals(addr(200), map.getAddress(BigInteger.valueOf(10)));
	}

	@Test
	public void testGetIndexAtOrAfterWithHitAtAddress() {
		assertEquals(5, map.getIndexAtOrAfter(addr(105)).intValue());
	}

	@Test
	public void testGetIndexAtOrAfterWithAddressBeforeAny() {
		assertEquals(0, map.getIndexAtOrAfter(addr(50)).intValue());
	}

	@Test
	public void testGetIndexAtOrAfterWithAddressAtBeginningOfRange() {
		assertEquals(0, map.getIndexAtOrAfter(addr(100)).intValue());
	}

	@Test
	public void testGetIndexAtOrAfterWithAddressBiggerThanAnyReturnsLargestAddress() {
		assertEquals(30, map.getIndexAtOrAfter(addr(405)).intValue());
	}

	@Test
	public void testGetAddresSet() {
		FieldSelection selection = new FieldSelection();
		selection.addRange(BigInteger.valueOf(5), BigInteger.valueOf(15));
		AddressSet addressSet = map.getAddressSet(selection);
		assertEquals(10, addressSet.getNumAddresses());
		assertTrue(addressSet.contains(addr(105), addr(109)));
		assertTrue(!addressSet.contains(addr(110)));
		assertTrue(addressSet.contains(addr(200), addr(204)));
		assertTrue(!addressSet.contains(addr(110)));
		assertTrue(!addressSet.contains(addr(199)));
		assertTrue(!addressSet.contains(addr(205)));
	}

	@Test
	public void testGetFullAddressSet() {
		FieldSelection selection = new FieldSelection();
		selection.addRange(BigInteger.valueOf(0), BigInteger.valueOf(500));
		AddressSet addressSet = map.getAddressSet(selection);
		assertEquals(30, addressSet.getNumAddresses());
	}

	@Test
	public void testGetFieldSelectionWithAddressOutsideView() {
		FieldSelection selection = new FieldSelection();
		selection.addRange(BigInteger.valueOf(50), BigInteger.valueOf(100));
		AddressSet addressSet = map.getAddressSet(selection);
		assertTrue(addressSet.isEmpty());
	}

	@Test
	public void testGetFieldSelection() {
		AddressSet set = new AddressSet();
		set.addRange(addr(105), addr(109));
		set.addRange(addr(200), addr(204));

		FieldSelection fieldSelection = map.getFieldSelection(set);
		assertEquals(1, fieldSelection.getNumRanges());
		FieldRange fieldRange = fieldSelection.getFieldRange(0);
		assertEquals(BigInteger.valueOf(5), fieldRange.getStart().getIndex());
		assertEquals(BigInteger.valueOf(15), fieldRange.getEnd().getIndex());
	}

	@Test
	public void testGetMaxIndex() {
		assertEquals(9, map.getMaxIndex(addr(105)).intValue());
		assertEquals(9, map.getMaxIndex(addr(100)).intValue());
		assertEquals(29, map.getMaxIndex(addr(309)).intValue());
		assertEquals(29, map.getMaxIndex(addr(310)).intValue());
		assertNull(map.getMaxIndex(addr(0)));
	}

	@Test
	public void testGetMinIndex() {
		assertEquals(0, map.getMinIndex(addr(105)).intValue());
		assertEquals(0, map.getMinIndex(addr(100)).intValue());
		assertEquals(20, map.getMinIndex(addr(309)).intValue());
		assertEquals(20, map.getMinIndex(addr(310)).intValue());
		assertNull(map.getMinIndex(addr(0)));
	}

}
