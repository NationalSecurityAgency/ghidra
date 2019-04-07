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
package ghidra.util;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

import generic.util.UnsignedDataUtils;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class UnsignedDataUtilsTest extends AbstractGhidraHeadedIntegrationTest {

	@Test
	public void testByteGreaterThan() {
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan((byte) 0, (byte) 0));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan((byte) 1, (byte) 2));
		assertTrue(UnsignedDataUtils.unsignedGreaterThan((byte) 0xff, (byte) 0xee));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan((byte) 1, (byte) 0xbb));
		assertTrue(UnsignedDataUtils.unsignedGreaterThan((byte) 0xbb, (byte) 1));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan((byte) 0, (byte) 2));
		assertTrue(UnsignedDataUtils.unsignedGreaterThan((byte) 2, (byte) 0));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan((byte) 0, (byte) 0xaa));
		assertTrue(UnsignedDataUtils.unsignedGreaterThan((byte) 0xaa, (byte) 0));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan((byte) 25, (byte) 25));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan((byte) 0xee, (byte) 0xee));
	}

	@Test
	public void testByteGreaterThanOrEqual() {
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual((byte) 0, (byte) 0));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThanOrEqual((byte) 1, (byte) 2));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual((byte) 0xff, (byte) 0xee));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThanOrEqual((byte) 1, (byte) 0xbb));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual((byte) 0xbb, (byte) 1));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThanOrEqual((byte) 0, (byte) 2));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual((byte) 2, (byte) 0));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThanOrEqual((byte) 0, (byte) 0xaa));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual((byte) 0xaa, (byte) 0));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual((byte) 25, (byte) 25));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual((byte) 0xee, (byte) 0xee));
	}

	@Test
	public void testByteLessThan() {
		assertTrue(!UnsignedDataUtils.unsignedLessThan((byte) 0, (byte) 0));
		assertTrue(UnsignedDataUtils.unsignedLessThan((byte) 1, (byte) 2));
		assertTrue(!UnsignedDataUtils.unsignedLessThan((byte) 0xff, (byte) 0xee));
		assertTrue(UnsignedDataUtils.unsignedLessThan((byte) 1, (byte) 0xbb));
		assertTrue(!UnsignedDataUtils.unsignedLessThan((byte) 0xbb, (byte) 1));
		assertTrue(UnsignedDataUtils.unsignedLessThan((byte) 0, (byte) 2));
		assertTrue(!UnsignedDataUtils.unsignedLessThan((byte) 2, (byte) 0));
		assertTrue(UnsignedDataUtils.unsignedLessThan((byte) 0, (byte) 0xaa));
		assertTrue(!UnsignedDataUtils.unsignedLessThan((byte) 0xaa, (byte) 0));
		assertTrue(!UnsignedDataUtils.unsignedLessThan((byte) 25, (byte) 25));
		assertTrue(!UnsignedDataUtils.unsignedLessThan((byte) 0xee, (byte) 0xee));
	}

	@Test
	public void testByteLessThanOrEqual() {
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual((byte) 0, (byte) 0));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual((byte) 1, (byte) 2));
		assertTrue(!UnsignedDataUtils.unsignedLessThanOrEqual((byte) 0xff, (byte) 0xee));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual((byte) 1, (byte) 0xbb));
		assertTrue(!UnsignedDataUtils.unsignedLessThanOrEqual((byte) 0xbb, (byte) 1));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual((byte) 0, (byte) 2));
		assertTrue(!UnsignedDataUtils.unsignedLessThanOrEqual((byte) 2, (byte) 0));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual((byte) 0, (byte) 0xaa));
		assertTrue(!UnsignedDataUtils.unsignedLessThanOrEqual((byte) 0xaa, (byte) 0));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual((byte) 25, (byte) 25));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual((byte) 0xee, (byte) 0xee));
	}

	@Test
	public void testShortGreaterThan() {
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan((short) 0, (short) 0));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan((short) 1, (short) 2));
		assertTrue(UnsignedDataUtils.unsignedGreaterThan((short) 0xffff, (short) 0xeeee));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan((short) 1, (short) 0xbbbb));
		assertTrue(UnsignedDataUtils.unsignedGreaterThan((short) 0xbbbb, (short) 1));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan((short) 0, (short) 2));
		assertTrue(UnsignedDataUtils.unsignedGreaterThan((short) 2, (short) 0));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan((short) 0, (short) 0xaaaa));
		assertTrue(UnsignedDataUtils.unsignedGreaterThan((short) 0xaaaa, (short) 0));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan((short) 25, (short) 25));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan((short) 0xeeee, (short) 0xeeee));
	}

	@Test
	public void testShortGreaterThanOrEqual() {
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual((short) 0, (short) 0));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThanOrEqual((short) 1, (short) 2));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual((short) 0xffff, (short) 0xeeee));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThanOrEqual((short) 1, (short) 0xbbbb));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual((short) 0xbbbb, (short) 1));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThanOrEqual((short) 0, (short) 2));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual((short) 2, (short) 0));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThanOrEqual((short) 0, (short) 0xaaaa));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual((short) 0xaaaa, (short) 0));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual((short) 25, (short) 25));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual((short) 0xeeee, (short) 0xeeee));
	}

	@Test
	public void testShortLessThan() {
		assertTrue(!UnsignedDataUtils.unsignedLessThan((short) 0, (short) 0));
		assertTrue(UnsignedDataUtils.unsignedLessThan((short) 1, (short) 2));
		assertTrue(!UnsignedDataUtils.unsignedLessThan((short) 0xffff, (short) 0xeeee));
		assertTrue(UnsignedDataUtils.unsignedLessThan((short) 1, (short) 0xbbbb));
		assertTrue(!UnsignedDataUtils.unsignedLessThan((short) 0xbbbb, (short) 1));
		assertTrue(UnsignedDataUtils.unsignedLessThan((short) 0, (short) 2));
		assertTrue(!UnsignedDataUtils.unsignedLessThan((short) 2, (short) 0));
		assertTrue(UnsignedDataUtils.unsignedLessThan((short) 0, (short) 0xaaaa));
		assertTrue(!UnsignedDataUtils.unsignedLessThan((short) 0xaaaa, (short) 0));
		assertTrue(!UnsignedDataUtils.unsignedLessThan((short) 25, (short) 25));
		assertTrue(!UnsignedDataUtils.unsignedLessThan((short) 0xeeee, (short) 0xeeee));
	}

	@Test
	public void testShortLessThanOrEqual() {
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual((short) 0, (short) 0));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual((short) 1, (short) 2));
		assertTrue(!UnsignedDataUtils.unsignedLessThanOrEqual((short) 0xffff, (short) 0xeeee));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual((short) 1, (short) 0xbbbb));
		assertTrue(!UnsignedDataUtils.unsignedLessThanOrEqual((short) 0xbbbb, (short) 1));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual((short) 0, (short) 2));
		assertTrue(!UnsignedDataUtils.unsignedLessThanOrEqual((short) 2, (short) 0));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual((short) 0, (short) 0xaaaa));
		assertTrue(!UnsignedDataUtils.unsignedLessThanOrEqual((short) 0xaaaa, (short) 0));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual((short) 25, (short) 25));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual((short) 0xeeee, (short) 0xeeee));
	}

	/*********************************/

	@Test
	public void testIntGreaterThan() {
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan(0, 0));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan(1, 2));
		assertTrue(UnsignedDataUtils.unsignedGreaterThan(0xffffffff, 0xeeeeeeee));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan(1, 0xbbbbbbbb));
		assertTrue(UnsignedDataUtils.unsignedGreaterThan(0xbbbbbbbb, 1));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan(0, 2));
		assertTrue(UnsignedDataUtils.unsignedGreaterThan(2, 0));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan(0, 0xaaaaaaaa));
		assertTrue(UnsignedDataUtils.unsignedGreaterThan(0xaaaaaaaa, 0));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan(25, 25));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan(0xeeeeeeee, 0xeeeeeeee));
	}

	@Test
	public void testIntGreaterThanOrEqual() {
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual(0, 0));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThanOrEqual(1, 2));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual(0xffffffff, 0xeeeeeeee));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThanOrEqual(1, 0xbbbbbbbb));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual(0xbbbbbbbb, 1));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThanOrEqual(0, 2));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual(2, 0));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThanOrEqual(0, 0xaaaaaaaa));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual(0xaaaaaaaa, 0));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual(25, 25));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual(0xeeeeeeee, 0xeeeeeeee));
	}

	@Test
	public void testIntLessThan() {
		assertTrue(!UnsignedDataUtils.unsignedLessThan(0, 0));
		assertTrue(UnsignedDataUtils.unsignedLessThan(1, 2));
		assertTrue(!UnsignedDataUtils.unsignedLessThan(0xffffffff, 0xeeeeeeee));
		assertTrue(UnsignedDataUtils.unsignedLessThan(1, 0xbbbbbbbb));
		assertTrue(!UnsignedDataUtils.unsignedLessThan(0xbbbbbbbb, 1));
		assertTrue(UnsignedDataUtils.unsignedLessThan(0, 2));
		assertTrue(!UnsignedDataUtils.unsignedLessThan(2, 0));
		assertTrue(UnsignedDataUtils.unsignedLessThan(0, 0xaaaaaaaa));
		assertTrue(!UnsignedDataUtils.unsignedLessThan(0xaaaaaaaa, 0));
		assertTrue(!UnsignedDataUtils.unsignedLessThan(25, 25));
		assertTrue(!UnsignedDataUtils.unsignedLessThan(0xeeeeeeee, 0xeeeeeeee));
	}

	@Test
	public void testIntLessThanOrEqual() {
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual(0, 0));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual(1, 2));
		assertTrue(!UnsignedDataUtils.unsignedLessThanOrEqual(0xffffffff, 0xeeeeeeee));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual(1, 0xbbbbbbbb));
		assertTrue(!UnsignedDataUtils.unsignedLessThanOrEqual(0xbbbbbbbb, 1));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual(0, 2));
		assertTrue(!UnsignedDataUtils.unsignedLessThanOrEqual(2, 0));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual(0, 0xaaaaaaaa));
		assertTrue(!UnsignedDataUtils.unsignedLessThanOrEqual(0xaaaaaaaa, 0));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual(25, 25));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual(0xeeeeeeee, 0xeeeeeeee));
	}

	/*********************************/

	@Test
	public void testLongGreaterThan() {
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan(0L, 0L));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan(1L, 2L));
		assertTrue(UnsignedDataUtils.unsignedGreaterThan(0xffffffffffffffffL, 0xeeeeeeeeeeeeeeeeL));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan(1L, 0xbbbbbbbbbbbbbbbbL));
		assertTrue(UnsignedDataUtils.unsignedGreaterThan(0xbbbbbbbbbbbbbbbbL, 1L));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan(0L, 2L));
		assertTrue(UnsignedDataUtils.unsignedGreaterThan(2L, 0L));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan(0L, 0xaaaaaaaaaaaaaaaaL));
		assertTrue(UnsignedDataUtils.unsignedGreaterThan(0xaaaaaaaaaaaaaaaaL, 0L));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThan(25L, 25L));
		assertTrue(
			!UnsignedDataUtils.unsignedGreaterThan(0xeeeeeeeeeeeeeeeeL, 0xeeeeeeeeeeeeeeeeL));
	}

	@Test
	public void testLongGreaterThanOrEqual() {
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual(0L, 0L));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThanOrEqual(1L, 2L));
		assertTrue(
			UnsignedDataUtils.unsignedGreaterThanOrEqual(0xffffffffffffffffL, 0xeeeeeeeeeeeeeeeeL));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThanOrEqual(1L, 0xbbbbbbbbbbbbbbbbL));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual(0xbbbbbbbbbbbbbbbbL, 1L));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThanOrEqual(0L, 2L));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual(2L, 0L));
		assertTrue(!UnsignedDataUtils.unsignedGreaterThanOrEqual(0L, 0xaaaaaaaaaaaaaaaaL));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual(0xaaaaaaaaaaaaaaaaL, 0L));
		assertTrue(UnsignedDataUtils.unsignedGreaterThanOrEqual(25L, 25L));
		assertTrue(
			UnsignedDataUtils.unsignedGreaterThanOrEqual(0xeeeeeeeeeeeeeeeeL, 0xeeeeeeeeeeeeeeeeL));
	}

	@Test
	public void testLongLessThan() {
		assertTrue(!UnsignedDataUtils.unsignedLessThan(0L, 0L));
		assertTrue(UnsignedDataUtils.unsignedLessThan(1L, 2L));
		assertTrue(!UnsignedDataUtils.unsignedLessThan(0xffffffffffffffffL, 0xeeeeeeeeeeeeeeeeL));
		assertTrue(UnsignedDataUtils.unsignedLessThan(1L, 0xbbbbbbbbbbbbbbbbL));
		assertTrue(!UnsignedDataUtils.unsignedLessThan(0xbbbbbbbbbbbbbbbbL, 1L));
		assertTrue(UnsignedDataUtils.unsignedLessThan(0L, 2L));
		assertTrue(!UnsignedDataUtils.unsignedLessThan(2L, 0L));
		assertTrue(UnsignedDataUtils.unsignedLessThan(0L, 0xaaaaaaaaaaaaaaaaL));
		assertTrue(!UnsignedDataUtils.unsignedLessThan(0xaaaaaaaaaaaaaaaaL, 0L));
		assertTrue(!UnsignedDataUtils.unsignedLessThan(25L, 25L));
		assertTrue(!UnsignedDataUtils.unsignedLessThan(0xeeeeeeeeeeeeeeeeL, 0xeeeeeeeeeeeeeeeeL));
	}

	@Test
	public void testLongLessThanOrEqual() {
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual(0L, 0L));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual(1L, 2L));
		assertTrue(
			!UnsignedDataUtils.unsignedLessThanOrEqual(0xffffffffffffffffL, 0xeeeeeeeeeeeeeeeeL));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual(1L, 0xbbbbbbbbbbbbbbbbL));
		assertTrue(!UnsignedDataUtils.unsignedLessThanOrEqual(0xbbbbbbbbbbbbbbbbL, 1L));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual(0L, 2L));
		assertTrue(!UnsignedDataUtils.unsignedLessThanOrEqual(2L, 0L));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual(0L, 0xaaaaaaaaaaaaaaaaL));
		assertTrue(!UnsignedDataUtils.unsignedLessThanOrEqual(0xaaaaaaaaaaaaaaaaL, 0L));
		assertTrue(UnsignedDataUtils.unsignedLessThanOrEqual(25L, 25L));
		assertTrue(
			UnsignedDataUtils.unsignedLessThanOrEqual(0xeeeeeeeeeeeeeeeeL, 0xeeeeeeeeeeeeeeeeL));
	}
}
