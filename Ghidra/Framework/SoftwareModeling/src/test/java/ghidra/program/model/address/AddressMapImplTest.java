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

import static org.junit.Assert.*;

import org.junit.*;

import generic.test.AbstractGenericTest;

public class AddressMapImplTest extends AbstractGenericTest {
	AddressSpace sp8;
	AddressSpace sp16;
	AddressSpace sp32;
	AddressSpace sp64;
	AddressSpace ov64;
	AddressSpace regSpace;
	AddressSpace stackSpace;
	SegmentedAddressSpace segSpace1;
	SegmentedAddressSpace segSpace2;
	AddressMapImpl map;

	Address[] addrs;

	@Before
	public void setUp() {

		sp8 = new GenericAddressSpace("ONE", 8, AddressSpace.TYPE_RAM, 0);
		sp16 = new GenericAddressSpace("TWO", 16, AddressSpace.TYPE_RAM, 1);
		sp32 = new GenericAddressSpace("THREE", 32, AddressSpace.TYPE_RAM, 2);
		sp64 = new GenericAddressSpace("FOUR", 64, AddressSpace.TYPE_RAM, 2);

		ov64 = new OverlayAddressSpace("four", sp64, 100, 0x1000, 0x1fff);

		segSpace1 = new SegmentedAddressSpace("SegSpaceOne", 3);
		segSpace2 = new SegmentedAddressSpace("SegSpaceTwo", 4);

		regSpace = new GenericAddressSpace("Register", 32, AddressSpace.TYPE_REGISTER, 0);
		stackSpace = new GenericAddressSpace("stack", 32, AddressSpace.TYPE_STACK, 0);

		map = new AddressMapImpl();

		addrs = new Address[31];
		addrs[0] = sp8.getAddress(0);
		addrs[1] = sp8.getAddress(0x0ff);
		addrs[2] = sp16.getAddress(0);
		addrs[3] = sp16.getAddress(0x0ff);
		addrs[4] = sp16.getAddress(0x0ffff);
		addrs[5] = sp32.getAddress(0);
		addrs[6] = sp32.getAddress(0x0ff);
		addrs[7] = sp32.getAddress(0x0ffff);
		addrs[8] = sp32.getAddress(0x0ffffff);
		addrs[9] = sp32.getAddress(0x0ffffffff);
		addrs[10] = sp64.getAddress(0);
		addrs[11] = sp64.getAddress(0x0ff);
		addrs[12] = sp64.getAddress(0x0ffff);
		addrs[13] = sp64.getAddress(0x0ffffff);
		addrs[14] = sp64.getAddress(0x0ffffffff);
		addrs[15] = sp64.getAddress(0x10ffffffffL);
		addrs[16] = sp64.getAddress(0x20ffffffffL);

		addrs[17] = segSpace1.getAddress(0, 0);
		addrs[18] = segSpace1.getAddress(0, 50);
		addrs[19] = segSpace1.getAddress(1, 0);
		addrs[20] = segSpace1.getAddress(1, 10);
		addrs[21] = segSpace2.getAddress(0, 0);
		addrs[22] = segSpace2.getAddress(0, 0xffff);
		addrs[23] = segSpace2.getAddress(0xf000, 0xffff);

		addrs[24] = regSpace.getAddress(0);
		addrs[25] = regSpace.getAddress(0x0ff);

		addrs[26] = stackSpace.getAddress(0x7fffffff);
		addrs[27] = stackSpace.getAddress(0);
		addrs[28] = stackSpace.getAddress(0x80000000);

		addrs[29] = ov64.getAddress(0x1100);
		addrs[30] = ov64.getAddress(0x2000);

	}

	@Test
	public void testGetIndex() {

		long[] values = new long[addrs.length];
		Address[] addrValues = new Address[addrs.length];

		for (int i = 0; i < addrs.length; i++) {
			values[i] = map.getKey(addrs[i]);
		}
//		
//		try {
//			ByteArrayOutputStream baos = new ByteArrayOutputStream();
//			ObjectOutputStream oos = new ObjectOutputStream(baos);
//			oos.writeObject(map);
//			oos.close();
//			
//			ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
//			ObjectInputStream ois = new ObjectInputStream(bais);
//			map = (AddressMap)ois.readObject();
//		} catch(Exception e) {
//			Assert.fail("Caught unexpected io exception");
//		}		
//		
		for (int i = 0; i < addrValues.length; i++) {
			addrValues[i] = map.decodeAddress(values[i]);
		}
		for (int i = 0; i < addrValues.length; i++) {
//			System.out.println("OrigAddress = " + addrs[i] +
//				", AddrValue = " + addrValues[i] +
//				", Long value = " + Long.toHexString(values[i]));
			Assert.assertEquals(addrs[i], addrValues[i]);
		}
	}

	@Test
	public void testGetEffectiveValue() {
		Assert.assertEquals(map.getKey(addrs[0]), map.getKey(addrs[0]));
		assertTrue(map.getKey(addrs[12]) == map.getKey(addrs[12]));

		SegmentedAddress segA = new SegmentedAddress(segSpace1, 0x1234, 5);
		long effValue = map.getKey(segA);
		SegmentedAddress segB = (SegmentedAddress) map.decodeAddress(effValue);
		Assert.assertEquals(0x1000, segB.getSegment());
		Assert.assertEquals(0x2345, segB.getSegmentOffset());

		GenericAddress addr = new GenericAddress(sp8, 0);
		effValue = map.getKey(addr);
		Address a = map.decodeAddress(effValue);
		Assert.assertEquals(addr, a);

	}

	@Test
	public void testRegisterAddress() {
		Address a = regSpace.getAddress(0);
		long key = map.getKey(a);
		Address b = map.decodeAddress(key);
		Assert.assertEquals(a, b);

		a = regSpace.getAddress(10);
		key = map.getKey(a);
		b = map.decodeAddress(key);
		Assert.assertEquals(a, b);
	}

	@Test
	public void testStackAddress() {
		Address a = stackSpace.getAddress(0);
		long key = map.getKey(a);
		Address b = map.decodeAddress(key);
		Assert.assertEquals(a, b);

		a = stackSpace.getAddress(10);
		key = map.getKey(a);
		b = map.decodeAddress(key);
		Assert.assertEquals(a, b);
	}

}
