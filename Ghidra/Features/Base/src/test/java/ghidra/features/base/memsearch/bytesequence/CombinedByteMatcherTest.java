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
package ghidra.features.base.memsearch.bytesequence;

import static org.junit.Assert.*;

import java.util.List;
import java.util.stream.StreamSupport;

import org.junit.Before;
import org.junit.Test;

import ghidra.features.base.memsearch.matcher.*;
import ghidra.features.base.memsearch.matcher.ByteMatcher.ByteMatch;

public class CombinedByteMatcherTest {
	private ByteMatcher xxxByteMatcher;
	private ByteMatcher yyyByteMatcher;
	private ByteMatcher zzzByteMatcher;
	private CombinedByteMatcher multiMatcher;

	@Before
	public void setUp() {

		xxxByteMatcher = new RegExByteMatcher("xxx", null);
		yyyByteMatcher = new RegExByteMatcher("yyy", null);
		zzzByteMatcher = new RegExByteMatcher("zzz", null);
		multiMatcher =
			new CombinedByteMatcher(List.of(xxxByteMatcher, yyyByteMatcher, zzzByteMatcher), null);
	}

	@Test
	public void textFindsOneEachPatterns() {
		List<ByteMatch> results = match("fooxxxbar,  fooyyybar, foozzzbar");
		assertEquals(3, results.size());
		assertEquals(new ByteMatch(3, 3, xxxByteMatcher), results.get(0));
		assertEquals(new ByteMatch(15, 3, yyyByteMatcher), results.get(1));
		assertEquals(new ByteMatch(26, 3, zzzByteMatcher), results.get(2));
	}

	@Test
	public void textFindsMutliplePatterns() {
		List<ByteMatch> results = match("xxxyyyzzzxxxyyyzzz");
		assertEquals(6, results.size());
		assertEquals(new ByteMatch(0, 3, xxxByteMatcher), results.get(0));
		assertEquals(new ByteMatch(9, 3, xxxByteMatcher), results.get(1));
		assertEquals(new ByteMatch(3, 3, yyyByteMatcher), results.get(2));
		assertEquals(new ByteMatch(12, 3, yyyByteMatcher), results.get(3));
		assertEquals(new ByteMatch(6, 3, zzzByteMatcher), results.get(4));
		assertEquals(new ByteMatch(15, 3, zzzByteMatcher), results.get(5));
	}

	@Test
	public void testNoMatches() {
		List<ByteMatch> results = match("There are no matches here!");
		assertEquals(0, results.size());
	}

	private List<ByteMatch> match(String s) {
		ExtendedByteSequence sequence = createByteSequence(s);
		Iterable<ByteMatch> match = multiMatcher.match(sequence);
		return StreamSupport.stream(match.spliterator(), false).toList();
	}

	private ExtendedByteSequence createByteSequence(String s) {
		ByteSequence main = new ByteArrayByteSequence(makeBytes(s));
		ByteSequence extra = new ByteArrayByteSequence(makeBytes(""));
		return new ExtendedByteSequence(main, extra, 0);
	}

	private byte[] makeBytes(String string) {
		byte[] bytes = new byte[string.length()];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) string.charAt(i);
		}
		return bytes;
	}

}
