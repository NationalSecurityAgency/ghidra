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
package ghidra.pcodeCPort.slghpatexpress;

import static org.junit.Assert.*;

import org.junit.Test;

public class EqualEquationTest {

	@Test
	public void testNormalRange() {
		assertTrue(EqualEquation.isValueInRange(0x1234, 0, 0xffff));
		assertFalse(EqualEquation.isValueInRange(-1, 0, 0xffff));
	}

	@Test
	public void testFullWidthUnsignedRange() {
		assertTrue(EqualEquation.isValueInRange(0, 0, -1));
		assertTrue(EqualEquation.isValueInRange(Long.MAX_VALUE, 0, -1));
		assertTrue(EqualEquation.isValueInRange(Long.MIN_VALUE, 0, -1));
		assertTrue(EqualEquation.isValueInRange(-1, 0, -1));
	}

	@Test
	public void testUnsignedRangeCrossingSignedBoundary() {
		assertFalse(EqualEquation.isValueInRange(4, 5, -2));
		assertTrue(EqualEquation.isValueInRange(5, 5, -2));
		assertTrue(EqualEquation.isValueInRange(Long.MAX_VALUE, 5, -2));
		assertTrue(EqualEquation.isValueInRange(Long.MIN_VALUE, 5, -2));
		assertTrue(EqualEquation.isValueInRange(-2, 5, -2));
		assertFalse(EqualEquation.isValueInRange(-1, 5, -2));
	}
}
