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
package ghidra.app.plugin.assembler.sleigh.expr;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.Test;

public class MaskedLongTest {
	@Test
	public void testShiftLeft() {
		assertEquals(MaskedLong.fromLong(0xfffffffffffffff8L), MaskedLong.ONES.shiftLeft(3));
		assertEquals(MaskedLong.ZERO, MaskedLong.ZERO.shiftLeft(3));
		assertEquals(MaskedLong.fromMaskAndValue(0x7, 0), MaskedLong.UNKS.shiftLeft(3));
	}

	@Test
	public void testShiftRightLogical() {
		assertEquals(MaskedLong.fromLong(0x1fffffffffffffffL),
			MaskedLong.ONES.shiftRightLogical(3));
		assertEquals(MaskedLong.ZERO, MaskedLong.ZERO.shiftRightLogical(3));
		assertEquals(MaskedLong.fromMaskAndValue(0xe000000000000000L, 0),
			MaskedLong.UNKS.shiftRightLogical(3));
	}

	@Test
	public void testShiftRight() {
		assertEquals(MaskedLong.ONES, MaskedLong.ONES.shiftRight(3));
		assertEquals(MaskedLong.ZERO, MaskedLong.ZERO.shiftRight(3));
		assertEquals(MaskedLong.UNKS, MaskedLong.UNKS.shiftRight(3));
	}

	@Test
	public void testInvShiftLeft() throws SolverException {
		assertEquals(MaskedLong.fromMaskAndValue(0x1fffffffffffffffL, 0x1fffffffffffffffL),
			MaskedLong.fromLong(0xfffffffffffffff8L).invShiftLeft(3));
		assertEquals(MaskedLong.fromMaskAndValue(0x1fffffffffffffffL, 0),
			MaskedLong.ZERO.invShiftLeft(3));
		assertEquals(MaskedLong.UNKS, MaskedLong.UNKS.invShiftLeft(3));

		try {
			MaskedLong.ONES.invShiftLeft(3);
			fail();
		}
		catch (SolverException e) {
			// pass
		}
	}

	@Test
	public void testInvShiftRight() throws SolverException {
		assertEquals(MaskedLong.fromMaskAndValue(0xfffffffffffffff8L, 0xfffffffffffffff8L),
			MaskedLong.ONES.invShiftRight(3));
		assertEquals(MaskedLong.fromMaskAndValue(0xfffffffffffffff8L, 0),
			MaskedLong.ZERO.invShiftRight(3));
		assertEquals(MaskedLong.UNKS, MaskedLong.UNKS.invShiftRight(3));

		try {
			MaskedLong.fromLong(0x4000000000000000L).invShiftRight(3);
			fail();
		}
		catch (SolverException e) {
			// pass
		}

		try {
			MaskedLong.fromLong(0xa000000000000000L).invShiftRight(3);
			fail();
		}
		catch (SolverException e) {
			// pass
		}

		assertEquals(MaskedLong.fromMaskAndValue(0x8000000000000000L, 0),
			MaskedLong.fromMaskAndValue(0x8000000000000000L, 0).invShiftRight(3));
		assertEquals(MaskedLong.fromMaskAndValue(0x8000000000000000L, 0x8000000000000000L),
			MaskedLong.fromMaskAndValue(0x8000000000000000L, 0x8000000000000000L).invShiftRight(3));
	}

	@Test
	public void testInvShiftRightLogical() throws SolverException {
		assertEquals(MaskedLong.fromMaskAndValue(0xfffffffffffffff8L, 0xfffffffffffffff8L),
			MaskedLong.fromMaskAndValue(0x1fffffffffffffffL,
				0x1fffffffffffffffL).invShiftRightLogical(3));
		assertEquals(MaskedLong.fromMaskAndValue(0xfffffffffffffff8L, 0),
			MaskedLong.fromMaskAndValue(0x1fffffffffffffffL, 0).invShiftRightLogical(3));
		assertEquals(MaskedLong.UNKS, MaskedLong.UNKS.invShiftRightLogical(3));

		try {
			MaskedLong.ONES.invShiftRightLogical(3);
			fail();
		}
		catch (SolverException e) {
			// pass
		}
	}
}
