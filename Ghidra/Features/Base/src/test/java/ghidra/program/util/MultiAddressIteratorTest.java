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
package ghidra.program.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.*;

public class MultiAddressIteratorTest extends AbstractGenericTest {

	private AddressSpace space;
	private AddressFactory factory;

	/** Creates new ProgramDiffTest */
	public MultiAddressIteratorTest() {
		super();
	}

	/**
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {

		space = new GenericAddressSpace("xx", 32, AddressSpace.TYPE_RAM, 0);
		factory = new DefaultAddressFactory(new AddressSpace[] { space });
	}

	/**
	 * @see TestCase#tearDown()
	 */
	@After
	public void tearDown() throws Exception {
		space = null;
		factory = null;
	}

	private Address addr(String address) {
		return factory.getAddress(address);
	}

	@Test
    public void test1() throws Exception {
		AddressSet as1 = new AddressSet();
		as1.addRange(addr("0x1001120"), addr("0x1001120"));
		AddressSet as2 = new AddressSet();
		as2.addRange(addr("0x1001126"), addr("0x1001126"));

		AddressSet multiSet = new AddressSet();
		multiSet.addRange(addr("0x1001120"), addr("0x1001120"));
		multiSet.addRange(addr("0x1001126"), addr("0x1001126"));
		AddressIterator ai;
		MultiAddressIterator iter;

		// Forward tests
		boolean forward = true;
		while (true) {
			ai = multiSet.getAddresses(forward);
			iter = new MultiAddressIterator(
				new AddressIterator[] { as1.getAddresses(forward), as2.getAddresses(forward) },
				forward);
			while (iter.hasNext()) {
				assertTrue(ai.hasNext());
				Address expectedAddress = ai.next();
				Address actualAddress = iter.next();
				assertEquals(expectedAddress, actualAddress);
			}

			ai = multiSet.getAddresses(forward);
			iter = new MultiAddressIterator(
				new AddressIterator[] { as2.getAddresses(forward), as1.getAddresses(forward) },
				forward);
			while (iter.hasNext()) {
				assertTrue(ai.hasNext());
				Address expectedAddress = ai.next();
				Address actualAddress = iter.next();
				assertEquals(expectedAddress, actualAddress);
			}
			if (!forward) {
				break;
			}
			forward = false;// Change to backwards and do again
		}
	}

	@Test
    public void testDualForwardAddressIterator() throws Exception {
		AddressSet as1 = new AddressSet();
		as1.addRange(addr("0x1001100"), addr("0x1001120"));
		as1.addRange(addr("0x1001150"), addr("0x1001180"));
		as1.addRange(addr("0x1001200"), addr("0x1001210"));
		as1.addRange(addr("0x1001260"), addr("0x1001280"));
		AddressSet as2 = new AddressSet();
		as2.addRange(addr("0x1001090"), addr("0x1001130"));
		as2.addRange(addr("0x1001170"), addr("0x1001190"));
		as2.addRange(addr("0x1001230"), addr("0x1001240"));
		as2.addRange(addr("0x1001250"), addr("0x1001270"));

		AddressSet multiSet = new AddressSet();
		multiSet.addRange(addr("0x1001090"), addr("0x1001130"));
		multiSet.addRange(addr("0x1001150"), addr("0x1001190"));
		multiSet.addRange(addr("0x1001200"), addr("0x1001210"));
		multiSet.addRange(addr("0x1001230"), addr("0x1001240"));
		multiSet.addRange(addr("0x1001250"), addr("0x1001280"));
		AddressIterator ai;
		MultiAddressIterator iter;

		// Forward tests
		boolean forward = true;
		while (true) {
			ai = multiSet.getAddresses(forward);
			iter = new MultiAddressIterator(
				new AddressIterator[] { as1.getAddresses(forward), as2.getAddresses(forward) },
				forward);
			while (iter.hasNext()) {
				assertTrue(ai.hasNext());
				Address expectedAddress = ai.next();
				Address actualAddress = iter.next();
				assertEquals(expectedAddress, actualAddress);
			}

			ai = multiSet.getAddresses(forward);
			iter = new MultiAddressIterator(
				new AddressIterator[] { as2.getAddresses(forward), as1.getAddresses(forward) },
				forward);
			while (iter.hasNext()) {
				assertTrue(ai.hasNext());
				Address expectedAddress = ai.next();
				Address actualAddress = iter.next();
				assertEquals(expectedAddress, actualAddress);
			}
			if (!forward) {
				break;
			}
			forward = false;// Change to backwards and do again
		}
	}

	@Test
    public void testTriIter1() throws Exception {
		AddressSet as1 = new AddressSet();
		as1.addRange(addr("0x1001120"), addr("0x1001120"));
		AddressSet as2 = new AddressSet();
		as2.addRange(addr("0x1001126"), addr("0x1001126"));
		AddressSet as3 = new AddressSet();
		as2.addRange(addr("0x100112a"), addr("0x100112a"));

		AddressSet multiSet = new AddressSet();
		multiSet.addRange(addr("0x1001120"), addr("0x1001120"));
		multiSet.addRange(addr("0x1001126"), addr("0x1001126"));
		multiSet.addRange(addr("0x100112a"), addr("0x100112a"));
		AddressIterator ai;
		MultiAddressIterator iter;

		// Forward tests
		boolean forward = true;
		while (true) {
			ai = multiSet.getAddresses(forward);
			iter = new MultiAddressIterator(new AddressIterator[] { as1.getAddresses(forward),
				as2.getAddresses(forward), as3.getAddresses(forward) }, forward);
			while (iter.hasNext()) {
				assertTrue(ai.hasNext());
				Address expectedAddress = ai.next();
				Address actualAddress = iter.next();
				assertEquals(expectedAddress, actualAddress);
			}

			ai = multiSet.getAddresses(forward);
			iter = new MultiAddressIterator(new AddressIterator[] { as1.getAddresses(forward),
				as3.getAddresses(forward), as2.getAddresses(forward) }, forward);
			while (iter.hasNext()) {
				assertTrue(ai.hasNext());
				Address expectedAddress = ai.next();
				Address actualAddress = iter.next();
				assertEquals(expectedAddress, actualAddress);
			}

			ai = multiSet.getAddresses(forward);
			iter = new MultiAddressIterator(new AddressIterator[] { as3.getAddresses(forward),
				as2.getAddresses(forward), as1.getAddresses(forward) }, forward);
			while (iter.hasNext()) {
				assertTrue(ai.hasNext());
				Address expectedAddress = ai.next();
				Address actualAddress = iter.next();
				assertEquals(expectedAddress, actualAddress);
			}

			ai = multiSet.getAddresses(forward);
			iter = new MultiAddressIterator(new AddressIterator[] { as3.getAddresses(forward),
				as1.getAddresses(forward), as2.getAddresses(forward) }, forward);
			while (iter.hasNext()) {
				assertTrue(ai.hasNext());
				Address expectedAddress = ai.next();
				Address actualAddress = iter.next();
				assertEquals(expectedAddress, actualAddress);
			}

			ai = multiSet.getAddresses(forward);
			iter = new MultiAddressIterator(new AddressIterator[] { as2.getAddresses(forward),
				as3.getAddresses(forward), as1.getAddresses(forward) }, forward);
			while (iter.hasNext()) {
				assertTrue(ai.hasNext());
				Address expectedAddress = ai.next();
				Address actualAddress = iter.next();
				assertEquals(expectedAddress, actualAddress);
			}

			ai = multiSet.getAddresses(forward);
			iter = new MultiAddressIterator(new AddressIterator[] { as2.getAddresses(forward),
				as1.getAddresses(forward), as3.getAddresses(forward) }, forward);
			while (iter.hasNext()) {
				assertTrue(ai.hasNext());
				Address expectedAddress = ai.next();
				Address actualAddress = iter.next();
				assertEquals(expectedAddress, actualAddress);
			}
			if (!forward) {
				break;
			}
			forward = false;// Change to backwards and do again
		}
	}

	@Test
    public void testThreeIterator() throws Exception {
		AddressSet as1 = new AddressSet();
		as1.addRange(addr("0x1001100"), addr("0x1001120"));
		as1.addRange(addr("0x1001150"), addr("0x1001180"));
		as1.addRange(addr("0x1001200"), addr("0x1001210"));
		as1.addRange(addr("0x1001260"), addr("0x1001280"));
		AddressSet as2 = new AddressSet();
		as2.addRange(addr("0x1001090"), addr("0x1001130"));
		as2.addRange(addr("0x1001170"), addr("0x1001190"));
		as2.addRange(addr("0x1001230"), addr("0x1001240"));
		as2.addRange(addr("0x1001250"), addr("0x1001270"));
		AddressSet as3 = new AddressSet();
		as3.addRange(addr("0x1001132"), addr("0x1001132"));
		as3.addRange(addr("0x1001175"), addr("0x1001175"));
		as3.addRange(addr("0x1001205"), addr("0x1001235"));

		AddressSet multiSet = new AddressSet();
		multiSet.addRange(addr("0x1001090"), addr("0x1001130"));
		multiSet.addRange(addr("0x1001132"), addr("0x1001132"));
		multiSet.addRange(addr("0x1001150"), addr("0x1001190"));
		multiSet.addRange(addr("0x1001200"), addr("0x1001240"));
		multiSet.addRange(addr("0x1001250"), addr("0x1001280"));
		AddressIterator ai;
		MultiAddressIterator iter;

		// Forward tests
		boolean forward = true;
		while (true) {
			ai = multiSet.getAddresses(forward);
			iter = new MultiAddressIterator(new AddressIterator[] { as1.getAddresses(forward),
				as2.getAddresses(forward), as3.getAddresses(forward) }, forward);
			while (iter.hasNext()) {
				assertTrue(ai.hasNext());
				Address expectedAddress = ai.next();
				Address actualAddress = iter.next();
				assertEquals(expectedAddress, actualAddress);
			}

			ai = multiSet.getAddresses(forward);
			iter = new MultiAddressIterator(new AddressIterator[] { as1.getAddresses(forward),
				as3.getAddresses(forward), as2.getAddresses(forward) }, forward);
			while (iter.hasNext()) {
				assertTrue(ai.hasNext());
				Address expectedAddress = ai.next();
				Address actualAddress = iter.next();
				assertEquals(expectedAddress, actualAddress);
			}

			ai = multiSet.getAddresses(forward);
			iter = new MultiAddressIterator(new AddressIterator[] { as2.getAddresses(forward),
				as3.getAddresses(forward), as1.getAddresses(forward) }, forward);
			while (iter.hasNext()) {
				assertTrue(ai.hasNext());
				Address expectedAddress = ai.next();
				Address actualAddress = iter.next();
				assertEquals(expectedAddress, actualAddress);
			}

			ai = multiSet.getAddresses(forward);
			iter = new MultiAddressIterator(new AddressIterator[] { as2.getAddresses(forward),
				as1.getAddresses(forward), as3.getAddresses(forward) }, forward);
			while (iter.hasNext()) {
				assertTrue(ai.hasNext());
				Address expectedAddress = ai.next();
				Address actualAddress = iter.next();
				assertEquals(expectedAddress, actualAddress);
			}

			ai = multiSet.getAddresses(forward);
			iter = new MultiAddressIterator(new AddressIterator[] { as3.getAddresses(forward),
				as2.getAddresses(forward), as1.getAddresses(forward) }, forward);
			while (iter.hasNext()) {
				assertTrue(ai.hasNext());
				Address expectedAddress = ai.next();
				Address actualAddress = iter.next();
				assertEquals(expectedAddress, actualAddress);
			}

			ai = multiSet.getAddresses(forward);
			iter = new MultiAddressIterator(new AddressIterator[] { as3.getAddresses(forward),
				as1.getAddresses(forward), as2.getAddresses(forward) }, forward);
			while (iter.hasNext()) {
				assertTrue(ai.hasNext());
				Address expectedAddress = ai.next();
				Address actualAddress = iter.next();
				assertEquals(expectedAddress, actualAddress);
			}
			if (!forward) {
				break;
			}
			forward = false;// Change to backwards and do again
		}
	}

	@Test
    public void testDefaultThreeIterator() throws Exception {
		AddressSet as1 = new AddressSet();
		as1.addRange(addr("0x1001100"), addr("0x1001120"));
		as1.addRange(addr("0x1001150"), addr("0x1001180"));
		as1.addRange(addr("0x1001200"), addr("0x1001210"));
		as1.addRange(addr("0x1001260"), addr("0x1001280"));
		AddressSet as2 = new AddressSet();
		as2.addRange(addr("0x1001090"), addr("0x1001130"));
		as2.addRange(addr("0x1001170"), addr("0x1001190"));
		as2.addRange(addr("0x1001230"), addr("0x1001240"));
		as2.addRange(addr("0x1001250"), addr("0x1001270"));
		AddressSet as3 = new AddressSet();
		as3.addRange(addr("0x1001132"), addr("0x1001132"));
		as3.addRange(addr("0x1001175"), addr("0x1001175"));
		as3.addRange(addr("0x1001205"), addr("0x1001235"));

		AddressSet multiSet = new AddressSet();
		multiSet.addRange(addr("0x1001090"), addr("0x1001130"));
		multiSet.addRange(addr("0x1001132"), addr("0x1001132"));
		multiSet.addRange(addr("0x1001150"), addr("0x1001190"));
		multiSet.addRange(addr("0x1001200"), addr("0x1001240"));
		multiSet.addRange(addr("0x1001250"), addr("0x1001280"));
		AddressIterator ai;
		MultiAddressIterator iter;

		// Forward tests
		boolean forward = true;
		ai = multiSet.getAddresses(forward);
		iter = new MultiAddressIterator(new AddressIterator[] { as1.getAddresses(forward),
			as2.getAddresses(forward), as3.getAddresses(forward) });
		while (iter.hasNext()) {
			assertTrue(ai.hasNext());
			Address expectedAddress = ai.next();
			Address actualAddress = iter.next();
			assertEquals(expectedAddress, actualAddress);
		}

		ai = multiSet.getAddresses(forward);
		iter = new MultiAddressIterator(new AddressIterator[] { as1.getAddresses(forward),
			as3.getAddresses(forward), as2.getAddresses(forward) });
		while (iter.hasNext()) {
			assertTrue(ai.hasNext());
			Address expectedAddress = ai.next();
			Address actualAddress = iter.next();
			assertEquals(expectedAddress, actualAddress);
		}

		ai = multiSet.getAddresses(forward);
		iter = new MultiAddressIterator(new AddressIterator[] { as2.getAddresses(forward),
			as3.getAddresses(forward), as1.getAddresses(forward) });
		while (iter.hasNext()) {
			assertTrue(ai.hasNext());
			Address expectedAddress = ai.next();
			Address actualAddress = iter.next();
			assertEquals(expectedAddress, actualAddress);
		}

		ai = multiSet.getAddresses(forward);
		iter = new MultiAddressIterator(new AddressIterator[] { as2.getAddresses(forward),
			as1.getAddresses(forward), as3.getAddresses(forward) });
		while (iter.hasNext()) {
			assertTrue(ai.hasNext());
			Address expectedAddress = ai.next();
			Address actualAddress = iter.next();
			assertEquals(expectedAddress, actualAddress);
		}

		ai = multiSet.getAddresses(forward);
		iter = new MultiAddressIterator(new AddressIterator[] { as3.getAddresses(forward),
			as2.getAddresses(forward), as1.getAddresses(forward) });
		while (iter.hasNext()) {
			assertTrue(ai.hasNext());
			Address expectedAddress = ai.next();
			Address actualAddress = iter.next();
			assertEquals(expectedAddress, actualAddress);
		}

		ai = multiSet.getAddresses(forward);
		iter = new MultiAddressIterator(new AddressIterator[] { as3.getAddresses(forward),
			as1.getAddresses(forward), as2.getAddresses(forward) });
		while (iter.hasNext()) {
			assertTrue(ai.hasNext());
			Address expectedAddress = ai.next();
			Address actualAddress = iter.next();
			assertEquals(expectedAddress, actualAddress);
		}
	}
}
