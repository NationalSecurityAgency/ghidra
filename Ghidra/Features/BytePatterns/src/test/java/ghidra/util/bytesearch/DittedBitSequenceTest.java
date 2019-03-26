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

import org.junit.Test;

public class DittedBitSequenceTest {

	@Test
	public void testDittedBitSequenceConstructor() {
		byte bits = (byte) 0xe0;     //11100000
		byte dits = (byte) 0xe7;     //11100111

		DittedBitSequence dSeq = new DittedBitSequence(new byte[] { bits }, new byte[] { dits });
		assertEquals("111..000", dSeq.getHexString());

	}

	@Test
	public void testDittedBitSequenceConstructor_2() {
		DittedBitSequence dSeq = new DittedBitSequence("0x048f", true);
		assertEquals("0x04 0x8f", dSeq.getHexString());

		dSeq = new DittedBitSequence("00000000", false);
		assertEquals("0x00", dSeq.getHexString());

		dSeq = new DittedBitSequence("11111111", false);
		assertEquals("0xff", dSeq.getHexString());

		dSeq = new DittedBitSequence("1111000000001111", false);
		assertEquals("0xf0 0x0f", dSeq.getHexString());

		dSeq = new DittedBitSequence("0.0.1.1.11111111", false);
		assertEquals("0.0.1.1. 0xff", dSeq.getHexString());

	}

	@Test
	public void testGetNumUncertainBits() {

		DittedBitSequence dSeq = new DittedBitSequence("0xffff", true);
		assertEquals(dSeq.getNumUncertainBits(), 0);

		dSeq = new DittedBitSequence("0x0000", true);
		assertEquals(dSeq.getNumUncertainBits(), 0);

		byte bits = (byte) 0xa0;    //10100000
		byte dits = (byte) 0x55;    //01010101

		dSeq = new DittedBitSequence(new byte[] { bits }, new byte[] { dits });
		assertEquals(dSeq.getNumUncertainBits(), 4);

	}

	@Test
	public void testGetLeastUpperBound() {
		DittedBitSequence zeros =
			new DittedBitSequence(new byte[] { 0 }, new byte[] { (byte) 0xff });
		DittedBitSequence ones =
			new DittedBitSequence(new byte[] { (byte) 0xff }, new byte[] { (byte) 0xff });

		byte evenDits = (byte) 0x55; //01010101
		byte oddDits = (byte) 0xaa;  //10101010

		DittedBitSequence evens = new DittedBitSequence(new byte[] { 0 }, new byte[] { evenDits });
		DittedBitSequence odds =
			new DittedBitSequence(new byte[] { (byte) 0xff }, new byte[] { oddDits });

		DittedBitSequence merge = new DittedBitSequence(odds, evens);
		assertEquals(0, merge.getNumFixedBits());
		assertEquals(8, merge.getNumUncertainBits());
		assertEquals("........", merge.getHexString());

		merge = new DittedBitSequence(ones, zeros);
		assertEquals(0, merge.getNumFixedBits());
		assertEquals(8, merge.getNumUncertainBits());
		assertEquals("........", merge.getHexString());

		merge = new DittedBitSequence(evens, zeros);
		assertEquals(4, merge.getNumFixedBits());
		assertEquals(4, merge.getNumUncertainBits());
		assertEquals(".0.0.0.0", merge.getHexString());

		merge = new DittedBitSequence(odds, ones);
		assertEquals(4, merge.getNumFixedBits());
		assertEquals(4, merge.getNumUncertainBits());
		assertEquals("1.1.1.1.", merge.getHexString());
	}

	@Test
	public void testGetNumInitialFixedBits() {
		DittedBitSequence uninitialized = new DittedBitSequence();
		assertEquals(0, uninitialized.getNumInitialFixedBits(0));
		assertEquals(0, uninitialized.getNumInitialFixedBits(1));

		DittedBitSequence lengthZero = new DittedBitSequence(new byte[0]);
		assertEquals(0, lengthZero.getNumInitialFixedBits(0));
		assertEquals(0, lengthZero.getNumInitialFixedBits(1));

		DittedBitSequence noDits = new DittedBitSequence("0x00ff");
		assertEquals(0, noDits.getNumInitialFixedBits(0));
		assertEquals(8, noDits.getNumInitialFixedBits(1));
		assertEquals(16, noDits.getNumInitialFixedBits(2));
		assertEquals(0, noDits.getNumInitialFixedBits(3));

		DittedBitSequence someDits = new DittedBitSequence("0.0.0.0.1.1.1.1.");
		assertEquals(0, someDits.getNumInitialFixedBits(0));
		assertEquals(4, someDits.getNumInitialFixedBits(1));
		assertEquals(8, someDits.getNumInitialFixedBits(2));
		assertEquals(0, someDits.getNumInitialFixedBits(3));

		DittedBitSequence allDits = new DittedBitSequence("................");
		assertEquals(0, allDits.getNumInitialFixedBits(0));
		assertEquals(0, allDits.getNumInitialFixedBits(1));
		assertEquals(0, allDits.getNumInitialFixedBits(2));
		assertEquals(0, allDits.getNumInitialFixedBits(3));

	}

}
