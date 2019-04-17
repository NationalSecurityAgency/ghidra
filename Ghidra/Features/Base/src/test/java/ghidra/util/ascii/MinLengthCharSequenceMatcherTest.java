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
package ghidra.util.ascii;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.model.data.StringDataType;

public class MinLengthCharSequenceMatcherTest extends AbstractGenericTest {

	@Test
	public void testBasic() {
		MinLengthCharSequenceMatcher matcher =
			new MinLengthCharSequenceMatcher(3, new AsciiCharSetRecognizer(), 1);

		int[] values = new int[] { 0, 1, 2, 'a', 'b', 'c', 'd', 3, 4, 5 };
		List<Sequence> matches = new ArrayList<>();
		for (int value : values) {
			if (matcher.addChar(value)) {
				matches.add(matcher.getSequence());
			}
		}

		assertEquals(1, matches.size());
		assertEquals(new Sequence(3, 6, StringDataType.dataType, false), matches.get(0));
	}

	@Test
	public void testMultiple() {
		MinLengthCharSequenceMatcher matcher =
			new MinLengthCharSequenceMatcher(3, new AsciiCharSetRecognizer(), 1);

		int[] values = new int[] { 0, 1, 2, 'a', 'b', 'c', 'd', 3, 4, 5, 'e', 'f', 'g', 0, 1 };
		List<Sequence> matches = new ArrayList<>();
		for (int value : values) {
			if (matcher.addChar(value)) {
				matches.add(matcher.getSequence());
			}
		}

		assertEquals(2, matches.size());
		assertEquals(new Sequence(3, 6, StringDataType.dataType, false), matches.get(0));
		assertEquals(new Sequence(10, 13, StringDataType.dataType, true), matches.get(1));
	}

	@Test
	public void testStringAtStart() {
		MinLengthCharSequenceMatcher matcher =
			new MinLengthCharSequenceMatcher(3, new AsciiCharSetRecognizer(), 1);

		int[] values = new int[] { 'a', 'b', 'c', 'd', 0, 1 };
		List<Sequence> matches = new ArrayList<>();
		for (int value : values) {
			if (matcher.addChar(value)) {
				matches.add(matcher.getSequence());
			}
		}

		assertEquals(1, matches.size());
		assertEquals(new Sequence(0, 4, StringDataType.dataType, true), matches.get(0));
	}

	@Test
	public void testStringAtEndNoZeroTermination() {
		MinLengthCharSequenceMatcher matcher =
			new MinLengthCharSequenceMatcher(3, new AsciiCharSetRecognizer(), 1);

		int[] values = new int[] { 0, 'a', 'b', 'c', 'd' };
		List<Sequence> matches = new ArrayList<>();
		for (int value : values) {
			if (matcher.addChar(value)) {
				matches.add(matcher.getSequence());
			}
		}
		assertEquals(0, matches.size());
		assertTrue(matcher.endSequence());
		assertEquals(new Sequence(1, 4, StringDataType.dataType, false), matcher.getSequence());
	}

	@Test
	public void testAlignment() {
		MinLengthCharSequenceMatcher matcher =
			new MinLengthCharSequenceMatcher(3, new AsciiCharSetRecognizer(), 2);

		int[] values = new int[] { 0, 'a', 'b', 'c', 'd', 0, 0 };
		List<Sequence> matches = new ArrayList<>();
		for (int value : values) {
			if (matcher.addChar(value)) {
				matches.add(matcher.getSequence());
			}
		}
		assertEquals(1, matches.size());
		assertEquals(new Sequence(2, 5, StringDataType.dataType, true), matches.get(0));
	}

}
