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
package ghidra.trace.database.target;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import ghidra.trace.database.target.ValueSpace.AddressDimension;
import ghidra.trace.database.target.ValueSpace.EntryKeyDimension;
import ghidra.util.database.DBCachedObjectStoreFactory.RecAddress;

public class ValueSpaceTest {
	@Test
	public void testAddressDistance() {
		AddressDimension dim = AddressDimension.INSTANCE;

		assertEquals(0.0, dim.distance(new RecAddress(0, 0), new RecAddress(0, 0)), 0.0);

		assertEquals(100.0, dim.distance(new RecAddress(0, 0), new RecAddress(0, 100)), 0.0);
		assertEquals(-100.0, dim.distance(new RecAddress(0, 100), new RecAddress(0, 0)), 0.0);
		assertEquals(Math.pow(2, 65), dim.distance(new RecAddress(0, 0), new RecAddress(2, 0)),
			0.0);
		assertEquals(-Math.pow(2, 65), dim.distance(new RecAddress(2, 0), new RecAddress(0, 0)),
			0.0);

		// 10000 instead of 100, because double precision will not detect just 100
		assertEquals(Math.pow(2, 65) + 10000,
			dim.distance(new RecAddress(0, 0), new RecAddress(2, 10000)), 0.0);
		assertEquals(-Math.pow(2, 65) - 10000,
			dim.distance(new RecAddress(2, 10000), new RecAddress(0, 0)), 0.0);
		assertEquals(Math.pow(2, 65) - 10000,
			dim.distance(new RecAddress(0, 10000), new RecAddress(2, 0)), 0.0);
		assertEquals(-Math.pow(2, 65) + 10000,
			dim.distance(new RecAddress(2, 0), new RecAddress(0, 10000)), 0.0);
	}

	@Test
	public void testAddressMid() {
		AddressDimension dim = AddressDimension.INSTANCE;

		assertEquals(new RecAddress(0, 100),
			dim.mid(new RecAddress(0, 100), new RecAddress(0, 100)));

		assertEquals(new RecAddress(0, 50), dim.mid(new RecAddress(0, 0), new RecAddress(0, 100)));
		assertEquals(new RecAddress(0, 50), dim.mid(new RecAddress(0, 100), new RecAddress(0, 0)));

		assertEquals(new RecAddress(0, 49), dim.mid(new RecAddress(0, 0), new RecAddress(0, 99)));
		assertEquals(new RecAddress(0, 49), dim.mid(new RecAddress(0, 99), new RecAddress(0, 0)));

		assertEquals(new RecAddress(1, 0), dim.mid(new RecAddress(0, 0), new RecAddress(2, 0)));
		assertEquals(new RecAddress(1, 0), dim.mid(new RecAddress(2, 0), new RecAddress(0, 0)));

		assertEquals(new RecAddress(1, 50), dim.mid(new RecAddress(0, 0), new RecAddress(2, 100)));
		assertEquals(new RecAddress(1, 50), dim.mid(new RecAddress(2, 100), new RecAddress(0, 0)));
		assertEquals(new RecAddress(1, 50), dim.mid(new RecAddress(0, 100), new RecAddress(2, 0)));
		assertEquals(new RecAddress(1, 50), dim.mid(new RecAddress(2, 0), new RecAddress(0, 100)));

		assertEquals(new RecAddress(0, Long.MIN_VALUE),
			dim.mid(new RecAddress(0, 0), new RecAddress(1, 0)));
		assertEquals(new RecAddress(0, Long.MIN_VALUE),
			dim.mid(new RecAddress(1, 0), new RecAddress(0, 0)));

		assertEquals(new RecAddress(0, Long.MAX_VALUE),
			dim.mid(new RecAddress(0, 0), new RecAddress(0, -1)));
		assertEquals(new RecAddress(0, Long.MAX_VALUE),
			dim.mid(new RecAddress(0, -1), new RecAddress(0, 0)));

		assertEquals(new RecAddress(0, Long.MIN_VALUE + 50),
			dim.mid(new RecAddress(0, 0), new RecAddress(1, 100)));
		assertEquals(new RecAddress(0, Long.MIN_VALUE + 50),
			dim.mid(new RecAddress(1, 100), new RecAddress(0, 0)));
		assertEquals(new RecAddress(0, Long.MIN_VALUE + 50),
			dim.mid(new RecAddress(0, 100), new RecAddress(1, 0)));
		assertEquals(new RecAddress(0, Long.MIN_VALUE + 50),
			dim.mid(new RecAddress(1, 0), new RecAddress(0, 100)));
	}

	@Test
	public void testEntryKeyDistance() {
		EntryKeyDimension dim = EntryKeyDimension.INSTANCE;

		assertEquals(0.0, dim.distance("", ""), 0.0);
		assertEquals(0.0, dim.distance("A", "A"), 0.0);
		// null is not a valid key, but because it's the "absolute max", the tree may ask
		assertEquals(0.0, dim.distance(null, null), 0.0);

		assertEquals(25.0 * (Double.MAX_VALUE / 128), dim.distance("A", "Z"), 0.0);
		assertEquals(-1.0 * (Double.MAX_VALUE / 128), dim.distance("B", "A"), 0.0);
		assertEquals(1.0 * (Double.MAX_VALUE / 128), dim.distance("AA", "BA"), 0.0);
		assertEquals(-1.0 * (Double.MAX_VALUE / 128), dim.distance("BA", "AA"), 0.0);

		assertEquals(1.0 * (Double.MAX_VALUE / 128) + 1.0 * (Double.MAX_VALUE / 128 / 128),
			dim.distance("AA", "BB"), 0.0);
		assertEquals(-1.0 * (Double.MAX_VALUE / 128) - 1.0 * (Double.MAX_VALUE / 128 / 128),
			dim.distance("BB", "AA"), 0.0);
		assertEquals(1.0 * (Double.MAX_VALUE / 128) - 1.0 * (Double.MAX_VALUE / 128 / 128),
			dim.distance("AB", "BA"), 0.0);
		assertEquals(-1.0 * (Double.MAX_VALUE / 128) + 1.0 * (Double.MAX_VALUE / 128 / 128),
			dim.distance("BA", "AB"), 0.0);
	}

	@Test
	public void testEntryKeyMid() {
		EntryKeyDimension dim = EntryKeyDimension.INSTANCE;

		assertEquals("A", dim.mid("A", "A"));
		assertEquals(null, dim.mid(null, null));

		assertEquals("@", dim.mid("", null));
		assertEquals("@", dim.mid(null, ""));

		assertEquals("M@", dim.mid("A", "Z"));
		assertEquals("M@", dim.mid("Z", "A"));
		assertEquals("M@", dim.mid("A\0", "Z\0"));

		assertEquals("M", dim.mid("A", "Y"));
		assertEquals("M", dim.mid("Y", "A"));

		assertEquals("MA", dim.mid("AA", "YA"));
		assertEquals("MA", dim.mid("YA", "AA"));

		assertEquals("N\1", dim.mid("AA", "ZA"));
		assertEquals("N\1@", dim.mid("AA", "ZB"));
		assertEquals("N\1@", dim.mid("ZB", "AA"));
	}
}
