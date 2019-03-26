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
package ghidra.bitpatterns.info;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.bitpatterns.info.ByteSequenceLengthFilter;

public class ByteSequenceLengthFilterTest extends AbstractGenericTest {

	@Test
	public void testNull() {
		ByteSequenceLengthFilter bsFilter = new ByteSequenceLengthFilter(1, 1);
		String result = bsFilter.filter(null);
		assertEquals(null, result);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testException1() {
		@SuppressWarnings("unused")
		ByteSequenceLengthFilter bsFilter = new ByteSequenceLengthFilter(3, 2);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testException2() {
		@SuppressWarnings("unused")
		ByteSequenceLengthFilter bsFilter = new ByteSequenceLengthFilter(1, -1);
	}

	@Test
	public void testPositiveIndex() {
		ByteSequenceLengthFilter bsFilter = new ByteSequenceLengthFilter(1, 2);
		String result = bsFilter.filter("a");
		assertEquals(null, result);
		result = bsFilter.filter("abcd");
		assertEquals("ab", result);
	}

	@Test
	public void testNegativeIndex() {
		ByteSequenceLengthFilter bsFilter = new ByteSequenceLengthFilter(-1, 2);
		String result = bsFilter.filter("abcd");
		assertEquals("cd", result);
	}

	@Test
	public void testMinimumLengthZero() {
		ByteSequenceLengthFilter bsFilter = new ByteSequenceLengthFilter(0, 0);
		String result = bsFilter.filter("aa");
		assertEquals("", result);
	}

}
