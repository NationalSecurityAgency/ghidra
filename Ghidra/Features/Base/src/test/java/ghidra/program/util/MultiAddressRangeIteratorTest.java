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

public class MultiAddressRangeIteratorTest extends AbstractGenericTest {

	private AddressSpace space;
	private AddressFactory factory;

	/** Creates new ProgramDiffTest */
	public MultiAddressRangeIteratorTest() {
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

	private AddressRange addrRange(String startAddress, String endAddress) {
		return new AddressRangeImpl(factory.getAddress(startAddress),
			factory.getAddress(endAddress));
	}

	@Test
    public void testForwardDualIterator() throws Exception {

		AddressSet as1 = new AddressSet();
		as1.addRange(addr("0x1001000"), addr("0x1001045"));
		as1.addRange(addr("0x1001080"), addr("0x1001120"));
		as1.addRange(addr("0x1001140"), addr("0x1001170"));
		as1.addRange(addr("0x1001200"), addr("0x1001300"));
		as1.addRange(addr("0x1001335"), addr("0x1001339"));
		as1.addRange(addr("0x1001420"), addr("0x1001460"));
		as1.addRange(addr("0x1001530"), addr("0x1001567"));
		as1.addRange(addr("0x1001620"), addr("0x1001634"));
		as1.addRange(addr("0x1001720"), addr("0x1001790"));

		AddressSet as2 = new AddressSet();
		as2.addRange(addr("0x1001000"), addr("0x1001045"));
		as2.addRange(addr("0x1001080"), addr("0x1001130"));
		as2.addRange(addr("0x1001140"), addr("0x1001153"));
		as2.addRange(addr("0x1001210"), addr("0x1001225"));
		as2.addRange(addr("0x1001315"), addr("0x1001391"));
		as2.addRange(addr("0x1001440"), addr("0x1001480"));
		as2.addRange(addr("0x1001500"), addr("0x1001548"));
		as2.addRange(addr("0x1001650"), addr("0x1001670"));
		as2.addRange(addr("0x1001690"), addr("0x1001713"));

		AddressRange[] addressRanges = new AddressRange[] { addrRange("0x1001000", "0x1001045"),
			addrRange("0x1001080", "0x1001120"), addrRange("0x1001121", "0x1001130"),
			addrRange("0x1001140", "0x1001153"), addrRange("0x1001154", "0x1001170"),
			addrRange("0x1001200", "0x100120f"), addrRange("0x1001210", "0x1001225"),
			addrRange("0x1001226", "0x1001300"), addrRange("0x1001315", "0x1001334"),
			addrRange("0x1001335", "0x1001339"), addrRange("0x100133a", "0x1001391"),
			addrRange("0x1001420", "0x100143f"), addrRange("0x1001440", "0x1001460"),
			addrRange("0x1001461", "0x1001480"), addrRange("0x1001500", "0x100152f"),
			addrRange("0x1001530", "0x1001548"), addrRange("0x1001549", "0x1001567"),
			addrRange("0x1001620", "0x1001634"), addrRange("0x1001650", "0x1001670"),
			addrRange("0x1001690", "0x1001713"), addrRange("0x1001720", "0x1001790") };

		boolean forward = true;
		AddressRangeIterator[] iters = new AddressRangeIterator[] { as1.getAddressRanges(forward),
			as2.getAddressRanges(forward) };
		MultiAddressRangeIterator multiIter = new MultiAddressRangeIterator(iters, true);
		for (int i = 0; i < addressRanges.length; i++) {
			assertTrue("Missing address range = " + addressRanges[i].toString(),
				multiIter.hasNext());
			assertEquals(addressRanges[i], multiIter.next());
		}
		assertEquals("Has extra address range(s).", false, multiIter.hasNext());
	}

	@Test
    public void testBackwardDualIterator() throws Exception {

		AddressSet as1 = new AddressSet();
		as1.addRange(addr("0x1001000"), addr("0x1001045"));
		as1.addRange(addr("0x1001080"), addr("0x1001120"));
		as1.addRange(addr("0x1001140"), addr("0x1001170"));
		as1.addRange(addr("0x1001200"), addr("0x1001300"));
		as1.addRange(addr("0x1001335"), addr("0x1001339"));
		as1.addRange(addr("0x1001420"), addr("0x1001460"));
		as1.addRange(addr("0x1001530"), addr("0x1001567"));
		as1.addRange(addr("0x1001620"), addr("0x1001634"));
		as1.addRange(addr("0x1001720"), addr("0x1001790"));

		AddressSet as2 = new AddressSet();
		as2.addRange(addr("0x1001000"), addr("0x1001045"));
		as2.addRange(addr("0x1001080"), addr("0x1001130"));
		as2.addRange(addr("0x1001140"), addr("0x1001153"));
		as2.addRange(addr("0x1001210"), addr("0x1001225"));
		as2.addRange(addr("0x1001315"), addr("0x1001391"));
		as2.addRange(addr("0x1001440"), addr("0x1001480"));
		as2.addRange(addr("0x1001500"), addr("0x1001548"));
		as2.addRange(addr("0x1001650"), addr("0x1001670"));
		as2.addRange(addr("0x1001690"), addr("0x1001713"));

		AddressRange[] addressRanges = new AddressRange[] { addrRange("0x1001720", "0x1001790"),
			addrRange("0x1001690", "0x1001713"), addrRange("0x1001650", "0x1001670"),
			addrRange("0x1001620", "0x1001634"), addrRange("0x1001549", "0x1001567"),
			addrRange("0x1001530", "0x1001548"), addrRange("0x1001500", "0x100152f"),
			addrRange("0x1001461", "0x1001480"), addrRange("0x1001440", "0x1001460"),
			addrRange("0x1001420", "0x100143f"), addrRange("0x100133a", "0x1001391"),
			addrRange("0x1001335", "0x1001339"), addrRange("0x1001315", "0x1001334"),
			addrRange("0x1001226", "0x1001300"), addrRange("0x1001210", "0x1001225"),
			addrRange("0x1001200", "0x100120f"), addrRange("0x1001154", "0x1001170"),
			addrRange("0x1001140", "0x1001153"), addrRange("0x1001121", "0x1001130"),
			addrRange("0x1001080", "0x1001120"), addrRange("0x1001000", "0x1001045") };

		boolean forward = false;
		AddressRangeIterator[] iters = new AddressRangeIterator[] { as1.getAddressRanges(forward),
			as2.getAddressRanges(forward) };
		MultiAddressRangeIterator multiIter = new MultiAddressRangeIterator(iters, false);
		for (int i = 0; i < addressRanges.length; i++) {
			assertTrue("Missing address range = " + addressRanges[i].toString(),
				multiIter.hasNext());
			assertEquals(addressRanges[i], multiIter.next());
		}
		assertEquals("Has extra address range(s).", false, multiIter.hasNext());
	}

	@Test
    public void testForwardTriIterator() throws Exception {

		AddressSet as1 = new AddressSet();
		as1.addRange(addr("0x1001000"), addr("0x1001045"));
		as1.addRange(addr("0x1001080"), addr("0x1001120"));
		as1.addRange(addr("0x1001140"), addr("0x1001170"));
		as1.addRange(addr("0x1001200"), addr("0x1001300"));
		as1.addRange(addr("0x1001335"), addr("0x1001339"));
		as1.addRange(addr("0x1001420"), addr("0x1001460"));
		as1.addRange(addr("0x1001530"), addr("0x1001567"));
		as1.addRange(addr("0x1001620"), addr("0x1001634"));
		as1.addRange(addr("0x1001720"), addr("0x1001790"));

		AddressSet as2 = new AddressSet();
		as2.addRange(addr("0x1001000"), addr("0x1001045"));
		as2.addRange(addr("0x1001080"), addr("0x1001130"));
		as2.addRange(addr("0x1001140"), addr("0x1001153"));
		as2.addRange(addr("0x1001210"), addr("0x1001225"));
		as2.addRange(addr("0x1001315"), addr("0x1001391"));
		as2.addRange(addr("0x1001440"), addr("0x1001480"));
		as2.addRange(addr("0x1001500"), addr("0x1001548"));
		as2.addRange(addr("0x1001650"), addr("0x1001670"));
		as2.addRange(addr("0x1001690"), addr("0x1001713"));

		AddressSet as3 = new AddressSet();
		as3.addRange(addr("0x1001000"), addr("0x1001045"));
		as3.addRange(addr("0x1001218"), addr("0x1001222"));
		as3.addRange(addr("0x1001310"), addr("0x1001395"));
		as3.addRange(addr("0x1001450"), addr("0x1001510"));
		as3.addRange(addr("0x1001675"), addr("0x1001680"));

		AddressRange[] addressRanges = new AddressRange[] { addrRange("0x1001000", "0x1001045"),
			addrRange("0x1001080", "0x1001120"), addrRange("0x1001121", "0x1001130"),
			addrRange("0x1001140", "0x1001153"), addrRange("0x1001154", "0x1001170"),
			addrRange("0x1001200", "0x100120f"), addrRange("0x1001210", "0x1001217"),
			addrRange("0x1001218", "0x1001222"), addrRange("0x1001223", "0x1001225"),
			addrRange("0x1001226", "0x1001300"), addrRange("0x1001310", "0x1001314"),
			addrRange("0x1001315", "0x1001334"), addrRange("0x1001335", "0x1001339"),
			addrRange("0x100133a", "0x1001391"), addrRange("0x1001392", "0x1001395"),
			addrRange("0x1001420", "0x100143f"), addrRange("0x1001440", "0x100144f"),
			addrRange("0x1001450", "0x1001460"), addrRange("0x1001461", "0x1001480"),
			addrRange("0x1001481", "0x10014ff"), addrRange("0x1001500", "0x1001510"),
			addrRange("0x1001511", "0x100152f"), addrRange("0x1001530", "0x1001548"),
			addrRange("0x1001549", "0x1001567"), addrRange("0x1001620", "0x1001634"),
			addrRange("0x1001650", "0x1001670"), addrRange("0x1001675", "0x1001680"),
			addrRange("0x1001690", "0x1001713"), addrRange("0x1001720", "0x1001790") };

		boolean forward = true;
		AddressRangeIterator[] iters = new AddressRangeIterator[] { as1.getAddressRanges(forward),
			as2.getAddressRanges(forward), as3.getAddressRanges(forward) };
		MultiAddressRangeIterator multiIter = new MultiAddressRangeIterator(iters, true);
		for (int i = 0; i < addressRanges.length; i++) {
			assertTrue("Missing address range = " + addressRanges[i].toString(),
				multiIter.hasNext());
			assertEquals(addressRanges[i], multiIter.next());
		}
		assertEquals("Has extra address range(s).", false, multiIter.hasNext());
	}

	@Test
    public void testBackwardTriIterator() throws Exception {

		AddressSet as1 = new AddressSet();
		as1.addRange(addr("0x1001000"), addr("0x1001045"));
		as1.addRange(addr("0x1001080"), addr("0x1001120"));
		as1.addRange(addr("0x1001140"), addr("0x1001170"));
		as1.addRange(addr("0x1001200"), addr("0x1001300"));
		as1.addRange(addr("0x1001335"), addr("0x1001339"));
		as1.addRange(addr("0x1001420"), addr("0x1001460"));
		as1.addRange(addr("0x1001530"), addr("0x1001567"));
		as1.addRange(addr("0x1001620"), addr("0x1001634"));
		as1.addRange(addr("0x1001720"), addr("0x1001790"));

		AddressSet as2 = new AddressSet();
		as2.addRange(addr("0x1001000"), addr("0x1001045"));
		as2.addRange(addr("0x1001080"), addr("0x1001130"));
		as2.addRange(addr("0x1001140"), addr("0x1001153"));
		as2.addRange(addr("0x1001210"), addr("0x1001225"));
		as2.addRange(addr("0x1001315"), addr("0x1001391"));
		as2.addRange(addr("0x1001440"), addr("0x1001480"));
		as2.addRange(addr("0x1001500"), addr("0x1001548"));
		as2.addRange(addr("0x1001650"), addr("0x1001670"));
		as2.addRange(addr("0x1001690"), addr("0x1001713"));

		AddressSet as3 = new AddressSet();
		as3.addRange(addr("0x1001000"), addr("0x1001045"));
		as3.addRange(addr("0x1001218"), addr("0x1001222"));
		as3.addRange(addr("0x1001310"), addr("0x1001395"));
		as3.addRange(addr("0x1001450"), addr("0x1001510"));
		as3.addRange(addr("0x1001675"), addr("0x1001680"));

		AddressRange[] addressRanges = new AddressRange[] { addrRange("0x1001720", "0x1001790"),
			addrRange("0x1001690", "0x1001713"), addrRange("0x1001675", "0x1001680"),
			addrRange("0x1001650", "0x1001670"), addrRange("0x1001620", "0x1001634"),
			addrRange("0x1001549", "0x1001567"), addrRange("0x1001530", "0x1001548"),
			addrRange("0x1001511", "0x100152f"), addrRange("0x1001500", "0x1001510"),
			addrRange("0x1001481", "0x10014ff"), addrRange("0x1001461", "0x1001480"),
			addrRange("0x1001450", "0x1001460"), addrRange("0x1001440", "0x100144f"),
			addrRange("0x1001420", "0x100143f"), addrRange("0x1001392", "0x1001395"),
			addrRange("0x100133a", "0x1001391"), addrRange("0x1001335", "0x1001339"),
			addrRange("0x1001315", "0x1001334"), addrRange("0x1001310", "0x1001314"),
			addrRange("0x1001226", "0x1001300"), addrRange("0x1001223", "0x1001225"),
			addrRange("0x1001218", "0x1001222"), addrRange("0x1001210", "0x1001217"),
			addrRange("0x1001200", "0x100120f"), addrRange("0x1001154", "0x1001170"),
			addrRange("0x1001140", "0x1001153"), addrRange("0x1001121", "0x1001130"),
			addrRange("0x1001080", "0x1001120"), addrRange("0x1001000", "0x1001045") };

		boolean forward = false;
		AddressRangeIterator[] iters = new AddressRangeIterator[] { as1.getAddressRanges(forward),
			as2.getAddressRanges(forward), as3.getAddressRanges(forward) };
		MultiAddressRangeIterator multiIter = new MultiAddressRangeIterator(iters, false);
		for (int i = 0; i < addressRanges.length; i++) {
			assertTrue("Missing address range = " + addressRanges[i].toString(),
				multiIter.hasNext());
			assertEquals(addressRanges[i], multiIter.next());
		}
		assertEquals("Has extra address range(s).", false, multiIter.hasNext());
	}
}
